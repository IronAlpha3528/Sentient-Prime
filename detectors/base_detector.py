from abc import ABC, abstractmethod


class BaseDetector(ABC):
    @abstractmethod
    def load_model(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def predict(self, data: dict) -> dict:
        raise NotImplementedError
