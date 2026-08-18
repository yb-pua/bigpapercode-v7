"""离线特征缓存构建：全库 LFW → npy（InsightFace buffalo_l 512 维）。

用法：python experiments/build_cache.py [--backend insightface|dlib]
     [--limit N]  # 仅前 N 张（测试用）
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.data_loader import LFWLoader
from core.face_embedder import EmbeddingCache, FaceEmbedder
from data_config import CACHE_DIR, INSIGHTFACE_ROOT, LFW_DIR


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="insightface")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--image-list", default=None,
                    help="JSON 文件，[{'person','image'},...]；不指定则全库")
    args = ap.parse_args()

    loader = LFWLoader(LFW_DIR)
    if not loader.is_available():
        print("LFW not available at:", LFW_DIR)
        return 1
    if args.image_list:
        import json
        all_images = json.loads(Path(args.image_list).read_text(encoding="utf-8"))
    else:
        all_images = []
        for person in loader.persons:
            all_images.extend(
                f"{person}/{img}" for img in loader.person_images(person))
    if args.limit:
        all_images = all_images[:args.limit]
    print(f"LFW: {len(loader.persons)} persons, {len(all_images)} images")

    if args.image_list:
        for rel in all_images:
            if not (Path(LFW_DIR) / rel).exists():
                raise SystemExit(f"missing image: {rel}")
    def _abs(rel: str) -> str:
        return str(Path(LFW_DIR) / rel)

    embedder = FaceEmbedder(backend=args.backend, model_root=INSIGHTFACE_ROOT)
    print("backend:", args.backend, "available:", embedder.is_available(),
          "status:", embedder.status)
    cache = EmbeddingCache(str(CACHE_DIR), embedder)
    t0 = time.time()
    embs = cache.build([_abs(p) for p in all_images], workers=args.workers)
    dt = time.time() - t0
    n_ok = len(embs)
    print(f"extracted {n_ok}/{len(all_images)} in {dt:.1f}s "
          f"({dt / max(1, n_ok):.3f}s/img)")
    if n_ok < len(all_images):
        print(f"WARNING: {len(all_images) - n_ok} images failed")
    meta = {
        "backend": args.backend,
        "n_images": len(all_images),
        "n_extracted": n_ok,
        "seconds": dt,
        "status": embedder.status,
    }
    (CACHE_DIR / f"meta_{args.backend}.json").write_text(
        json.dumps(meta), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())