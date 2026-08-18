"""
LFW 数据加载与分层采样。

采样分层（与数据规约一致）：
    ≥2 张：1680 人（跨条件双样本：录入 1 张 / 验证 1 张）
    ≥5 张：423 人（投票主档：注册 5 张 / 验证 1 张）
    ≥8 张：217 人；≥10 张：158 人
异人配对：≥5000 对。
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from .common import get_rng


class LFWLoader:
    def __init__(self, lfw_dir: str):
        self.lfw_dir = Path(lfw_dir)
        self.persons: Dict[str, List[str]] = {}
        if self.lfw_dir.is_dir():
            self._load_persons()

    def _load_persons(self):
        for person_dir in sorted(self.lfw_dir.iterdir()):
            if person_dir.is_dir():
                images = sorted(
                    str(p) for p in person_dir.glob("*.jpg")
                    if p.is_file()
                )
                if images:
                    self.persons[person_dir.name] = images

    def is_available(self) -> bool:
        return len(self.persons) > 0

    def load_image(self, rel_path: str) -> Optional[np.ndarray]:
        """按缓存相对路径加载 RGB 图像（np.uint8, HxWx3）。"""
        try:
            from PIL import Image
            img = Image.open(self.lfw_dir / rel_path).convert("RGB")
            return np.asarray(img, dtype=np.uint8)
        except Exception:
            return None

    def person_images(self, person: str) -> List[str]:
        return self.persons.get(person, [])

    def stats(self) -> Dict[str, int]:
        counts = [len(v) for v in self.persons.values()]
        return {
            "total_persons": len(self.persons),
            "total_images": sum(counts),
            "ge2": sum(1 for c in counts if c >= 2),
            "ge5": sum(1 for c in counts if c >= 5),
            "ge8": sum(1 for c in counts if c >= 8),
            "ge10": sum(1 for c in counts if c >= 10),
        }

    def cohort(self, min_images: int, max_persons: Optional[int] = None,
               seed: Optional[int] = None) -> List[str]:
        """取满足最少张数的人群（固定顺序，可限量）。"""
        eligible = sorted(p for p, imgs in self.persons.items() if len(imgs) >= min_images)
        if max_persons is not None and len(eligible) > max_persons:
            rng = get_rng(seed)
            eligible = list(rng.choice(eligible, max_persons, replace=False))
            eligible = sorted(eligible)
        return eligible

    def sample_pairs(self, num_genuine: int, num_impostor: int,
                     min_images: int = 2, seed: Optional[int] = None) -> List[Dict]:
        """跨条件采样：真配对（同人两图，录入/验证各 1 张）、异人配对≥2 张人群。"""
        rng = get_rng(seed)
        eligible = [p for p, imgs in self.persons.items() if len(imgs) >= min_images]
        pairs: List[Dict] = []

        for _ in range(num_genuine):
            person = str(rng.choice(eligible))
            images = self.person_images(person)
            idx = rng.choice(len(images), 2, replace=False)
            pairs.append({
                "type": "genuine",
                "person": person,
                "enroll_img": images[int(idx[0])],
                "verify_img": images[int(idx[1])],
            })

        for _ in range(num_impostor):
            p1, p2 = rng.choice(eligible, 2, replace=False)
            imgs1 = self.person_images(str(p1))
            imgs2 = self.person_images(str(p2))
            pairs.append({
                "type": "impostor",
                "person1": str(p1),
                "person2": str(p2),
                "enroll_img": imgs1[int(rng.randint(0, len(imgs1)))],
                "verify_img": imgs2[int(rng.randint(0, len(imgs2)))],
            })
        return pairs

    def sample_vote_cohort(self, num_images: int = 5,
                           seed: Optional[int] = None) -> List[Dict]:
        """投票主档：每人在其 ≥num_images 张中固定取前 num_images 张。"""
        people = self.cohort(num_images)
        rng = get_rng(seed)
        people = list(rng.choice(people, len(people), replace=False))
        return [{
            "person": p,
            "enroll_imgs": self.person_images(p)[:num_images],
            "verify_imgs": self.person_images(p)[num_images:],
        } for p in people]