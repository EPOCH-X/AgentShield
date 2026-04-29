"""
[R4] 임베딩 — all-MiniLM-L6-v2

384차원 벡터, CPU 동작.
"""

# TODO: [R4] 구현
# - SentenceTransformer("all-MiniLM-L6-v2") 초기화
# - encode() 래퍼

import torch
from sentence_transformers import SentenceTransformer
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

class MiniLMEmbeddingFunction(EmbeddingFunction):
    def __init__(self):
        # device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

    def __call__(self, input: Documents) -> Embeddings:
        embeddings = self.model.encode(input, show_progress_bar=False).tolist()
        return embeddings
