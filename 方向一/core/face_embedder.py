"""
人脸特征提取：InsightFace buffalo_l 512 维（主）/ dlib 128 维（消融对照），
可切换后端；离线 npy 缓存。

后端不可用 → 固定 SEED 合成嵌入（按身份分组带噪声相关，标注 simulated）。
"""

import json
import multiprocessing
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from .common import get_rng

try:
    from PIL import Image
except ImportError:
    Image = None


class FaceEmbedder:
    def __init__(self, backend: str = "insightface",
                 model_root: Optional[str] = None,
                 use_fallback: bool = True,
                 ctx_id: Optional[int] = None,
                 det_size: tuple = (640, 640)):
        self.backend = backend
        self.model_root = model_root
        self.use_fallback = use_fallback
        self.det_size = det_size
        if ctx_id is None:
            ctx_id = 0 if _cuda_available() else -1
        self.ctx_id = ctx_id
        self._app = None
        self._dlib_fr = None
        self._dlib_det = None
        self._loaded = False
        self.status = "unknown"

    # ------------------------------------------------------------------
    def _load(self) -> bool:
        if self._loaded:
            return self.status == "ok"
        self._loaded = True
        if self.backend == "insightface":
            try:
                from insightface.app import FaceAnalysis
                self._app = FaceAnalysis(name="buffalo_l", root=self.model_root,
                                         allowed_modules=["detection", "recognition"])
                self._app.prepare(ctx_id=self.ctx_id, det_size=self.det_size)
                self.status = "ok"
            except Exception:
                self._app = None
                self.status = "unavailable"
        elif self.backend == "dlib":
            try:
                import dlib
                self._dlib_det = dlib.get_frontal_face_detector()
                self._dlib_fr = dlib.face_recognition_model_v1(
                    str(Path("models/dlib_face_recognition_resnet_model_v1.dat")))
                self.status = "ok"
            except Exception:
                self._dlib_fr = None
                self.status = "unavailable"
        else:
            raise ValueError(f"unknown backend: {self.backend}")
        return self.status == "ok"

    def is_available(self) -> bool:
        return self._load()

    def embedding_dim(self) -> int:
        return 512 if self.backend == "insightface" else 128

    # ------------------------------------------------------------------
    def extract(self, image_path: str) -> np.ndarray:
        """单图特征提取。失败返回 None（不静默回退原图，计数失败样本）。"""
        if not self._load():
            if not self.use_fallback:
                return None
            return self._fallback_embedding(image_path)
        if self.backend == "insightface":
            try:
                img = np.array(Image.open(image_path).convert("RGB"))
                return self.extract_from_array(img)
            except Exception:
                return None
        if self.backend == "dlib":
            try:
                import dlib
                img = np.array(Image.open(image_path).convert("RGB"))
                dets = self._dlib_det(img, 1)
                if not dets:
                    return None
                shape = self._dlib_sp(img, dets[0])
                return np.asarray(
                    self._dlib_fr.compute_face_descriptor(img, shape), dtype=np.float32)
            except Exception:
                return None
        return None

    def extract_from_array(self, img: np.ndarray) -> np.ndarray:
        """内存图像数组特征提取（A2 扰动图像用）。失败返回 None。"""
        if not self._load():
            if not self.use_fallback:
                return None
            return self._fallback_embedding_from_array(img)
        if self.backend == "insightface":
            try:
                faces = self._app.get(img)
                if not faces:
                    return None
                return np.asarray(faces[0].embedding, dtype=np.float32)
            except Exception:
                return None
        return None

    def _fallback_embedding_from_array(self, img: np.ndarray) -> np.ndarray:
        from .common import sm3
        seed = int.from_bytes(sm3(img.tobytes())[:8], "little")
        base = np.zeros(self.embedding_dim(), dtype=np.float32)
        base[0] = 1.0
        rng = np.random.RandomState(seed)
        noise = rng.randn(self.embedding_dim()).astype(np.float32) * 0.12
        vec = base + noise
        return vec / (np.linalg.norm(vec) + 1e-12)

    def _dlib_sp(self, img: np.ndarray, rect):
        import dlib
        sp = dlib.shape_predictor(str(Path("models/shape_predictor_68_face_landmarks.dat")))
        return sp(img, rect)

    def _fallback_embedding(self, image_path: str) -> np.ndarray:
        """合成嵌入：人员名 → 身份种子（SM3），图像路径 → 噪声种子（SM3），
        同人同特征族（带噪声相关）。标注 simulated。"""
        from .common import sm3
        person = str(Path(image_path).parent.name)
        person_seed = int.from_bytes(sm3(person.encode("utf-8"))[:8], "little")
        img_seed = int.from_bytes(sm3(image_path.encode("utf-8"))[:8], "little")
        rng = get_rng(SEED_SALT ^ person_seed)
        base = rng.randn(self.embedding_dim()).astype(np.float32)
        base /= np.linalg.norm(base) + 1e-12
        rng2 = get_rng(SEED_SALT ^ img_seed)
        noise = rng2.randn(self.embedding_dim()).astype(np.float32) * 0.12
        vec = base + noise
        vec /= np.linalg.norm(vec) + 1e-12
        return vec

    def extract_batch(self, image_paths: List[str],
                      workers: Optional[int] = None) -> Dict[str, Optional[np.ndarray]]:
        """并行批量提取（spawn 多进程，每个 worker 独立加载 CPU 模型，避免 fork 错位）。"""
        n = min(workers or multiprocessing.cpu_count(), 8)
        out: Dict[str, Optional[np.ndarray]] = {}
        if n <= 1 or len(image_paths) <= 8:
            for p in image_paths:
                out[p] = self.extract(p)
            return out
        chunks = [image_paths[i::n] for i in range(n)]
        ctx = multiprocessing.get_context("spawn")
        cfg = (self.backend, self.model_root)
        with ctx.Pool(n) as pool:
            results = pool.map(_spawn_extract_worker,
                               [(chunk, cfg) for chunk in chunks])
        for chunk in results:
            out.update(chunk)
        return out

    def extract_batch_from_arrays(self, images: List[np.ndarray],
                                  workers: Optional[int] = None) -> List[Optional[np.ndarray]]:
        """并行批量提取（spawn 多进程，结果与输入对齐，避免 fork 死锁）。"""
        n = min(workers or multiprocessing.cpu_count(), 8)
        if n <= 1 or len(images) <= 8:
            return [self.extract_from_array(img) for img in images]
        chunks = [images[i::n] for i in range(n)]
        ctx = multiprocessing.get_context("spawn")
        cfg = (self.backend, self.model_root)
        with ctx.Pool(n) as pool:
            results = pool.map(_spawn_array_worker,
                               [(c, cfg) for c in chunks])
        # round-robin 分片（images[i::n]）后按 chunk 顺序拼接会打乱输入顺序，
        # 需按原跨步交错回填，保证返回与输入逐元素对齐。
        out = [None] * len(images)
        for i, chunk_results in enumerate(results):
            out[i::n] = chunk_results
        return out

    def _array_worker(self, images: List[np.ndarray]) -> List[Optional[np.ndarray]]:
        return [self.extract_from_array(img) for img in images]

    def _extract_worker(self, paths: List[str]) -> Dict[str, Optional[np.ndarray]]:
        return {p: self.extract(p) for p in paths}


SEED_SALT = 0xC0FFEE


def _spawn_extract_worker(args):
    """spawn worker：独立加载 CPU 模型并提取一批图。"""
    paths, (backend, model_root) = args
    embedder = FaceEmbedder(backend=backend, model_root=model_root, ctx_id=-1)
    return {p: embedder.extract(p) for p in paths}


def _spawn_array_worker(args):
    """spawn worker：独立加载 CPU 模型并提取一批内存图像数组。"""
    arrays, (backend, model_root) = args
    embedder = FaceEmbedder(backend=backend, model_root=model_root, ctx_id=-1)
    return [embedder.extract_from_array(img) for img in arrays]


def _cuda_available() -> bool:
    """onnxruntime 是否提供 CUDA 执行提供程序。"""
    try:
        import onnxruntime as ort
        return "CUDAExecutionProvider" in ort.get_available_providers()
    except Exception:
        return False


class EmbeddingCache:
    """离线特征缓存（npy）：按 backend+dim 建文件，一次性提取全库。"""

    def __init__(self, cache_dir: str, embedder: FaceEmbedder):
        self.cache_dir = Path(cache_dir)
        self.embedder = embedder
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.cache_dir / f"index_{embedder.backend}.json"
        self._data_path = self.cache_dir / f"embs_{embedder.backend}.npy"

    def has_cache(self) -> bool:
        return self._index_path.exists() and self._data_path.exists()

    def load(self) -> Dict[str, np.ndarray]:
        if not self.has_cache():
            return {}
        index = json.loads(self._index_path.read_text(encoding="utf-8"))
        data = np.load(self._data_path)
        return {k: data[i] for k, i in index.items()}

    def build(self, image_paths: List[str], workers: Optional[int] = None) -> Dict[str, np.ndarray]:
        """全量提取并落盘缓存。返回 {path: embedding}。"""
        existing = self.load() if self.has_cache() else {}
        missing = [p for p in image_paths if p not in existing]
        result = dict(existing)
        if missing:
            batch = self.embedder.extract_batch(missing, workers=workers)
            result.update({p: e for p, e in batch.items() if e is not None})
            self._save(result)
        return result

    def _save(self, embs: Dict[str, np.ndarray]) -> None:
        paths = sorted(embs.keys())
        arr = np.stack([embs[p] for p in paths]).astype(np.float32)
        np.save(self._data_path, arr)
        self._index_path.write_text(
            json.dumps({p: i for i, p in enumerate(paths)}), encoding="utf-8")