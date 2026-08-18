"""
图像级噪声扰动（OpenCV 五类）：高斯 / 亮度 / 旋转 / 模糊 / 遮挡。
强度梯度参数化，seed 可复现。
"""

from typing import Callable, Dict, List, Optional, Tuple

import numpy as np

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

from .common import get_rng

NOISE_TYPES = ["gaussian", "brightness", "rotation", "blur", "occlusion"]

# 各扰动类型的强度梯度（与 A2 实验共用）
INTENSITY_GRID: Dict[str, List[float]] = {
    "gaussian": [0.0, 0.02, 0.05, 0.10, 0.20, 0.30],
    "brightness": [1.0, 0.9, 0.8, 0.65, 0.5, 0.35],
    "rotation": [0.0, 3.0, 6.0, 10.0, 15.0, 20.0],
    "blur": [0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
    "occlusion": [0.0, 0.10, 0.15, 0.20, 0.25, 0.30],
}


def apply_noise(image: np.ndarray, noise_type: str, intensity: float,
                seed: Optional[int] = None) -> np.ndarray:
    """对图像施加指定扰动。seed 固定则结果可复现。"""
    if not CV2_AVAILABLE:
        return image
    fn = _NOISE_FUNCS[noise_type]
    return fn(image, intensity, seed)


def gaussian_noise(image: np.ndarray, sigma: float, seed: Optional[int] = None) -> np.ndarray:
    img = np.asarray(image)
    rng = get_rng(seed)
    noise = rng.randn(*img.shape[:2], 1 if img.ndim == 2 else img.shape[2]).astype(np.float32)
    out = img.astype(np.float32) + noise * (sigma * 255.0)
    return np.clip(out, 0, 255).astype(np.uint8)


def brightness(image: np.ndarray, factor: float, seed: Optional[int] = None) -> np.ndarray:
    out = np.asarray(image).astype(np.float32) * factor
    return np.clip(out, 0, 255).astype(np.uint8)


def rotation(image: np.ndarray, angle: float, seed: Optional[int] = None) -> np.ndarray:
    img = np.asarray(image)
    h, w = img.shape[:2]
    center = (w / 2.0, h / 2.0)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    return cv2.warpAffine(img, matrix, (w, h))


def gaussian_blur(image: np.ndarray, sigma: float, seed: Optional[int] = None) -> np.ndarray:
    k = max(3, int(round(sigma * 2)) | 1)
    return cv2.GaussianBlur(np.asarray(image), (k, k), sigma)


def occlusion(image: np.ndarray, ratio: float, seed: Optional[int] = None) -> np.ndarray:
    """中心遮挡：黑色矩形，面积占比 ratio。"""
    img = np.asarray(image).copy()
    h, w = img.shape[:2]
    area = ratio * h * w
    side = max(1, int(np.sqrt(area)))
    ch = min(h, side)
    cw = min(w, side)
    y0 = (h - ch) // 2
    x0 = (w - cw) // 2
    img[y0:y0 + ch, x0:x0 + cw] = 0
    return img


_NOISE_FUNCS: Dict[str, Callable] = {
    "gaussian": gaussian_noise,
    "brightness": brightness,
    "rotation": rotation,
    "blur": gaussian_blur,
    "occlusion": occlusion,
}


def noise_is_available() -> bool:
    return CV2_AVAILABLE