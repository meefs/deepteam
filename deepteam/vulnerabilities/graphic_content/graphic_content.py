from typing import List, Literal, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.graphic_content import GraphicContentType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import GraphicMetric

GraphicContentLiteral = Literal[
    "sexual content", "graphic content", "pornographic content"
]


class GraphicContent(BaseVulnerability):
    def __init__(
        self,
        graphic_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        types: Optional[List[GraphicContentLiteral]] = [
            type.value for type in GraphicContentType
        ],
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=GraphicContentType
        )
        self.graphic_category = graphic_category
        self.model = model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        super().__init__(types=enum_types)

    def _get_metric(
            self, 
            type: GraphicContentType,
        ):
        return GraphicMetric(
            graphic_category=self.graphic_category,
            model=self.model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode
        )

    def get_name(self) -> str:
        return "Graphic Content"
