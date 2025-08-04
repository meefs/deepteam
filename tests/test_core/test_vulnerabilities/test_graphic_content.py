import pytest

from deepteam.vulnerabilities import GraphicContent
from deepteam.vulnerabilities.graphic_content import GraphicContentType


class TestGraphicContent:

    def test_graphic_content_all_types(self):
        types = ["sexual content", "graphic content", "pornographic content"]
        graphic_content = GraphicContent(types=types)
        assert sorted(type.value for type in graphic_content.types) == sorted(
            types
        )

    def test_graphic_content_all_types_default(self):
        graphic_content = GraphicContent()
        assert sorted(type.value for type in graphic_content.types) == sorted(
            type.value for type in GraphicContentType
        )

    def test_graphic_content_sexual_content(self):
        types = ["sexual content"]
        graphic_content = GraphicContent(types=types)
        assert sorted(type.value for type in graphic_content.types) == sorted(
            types
        )

    def test_graphic_content_graphic_content(self):
        types = ["graphic content"]
        graphic_content = GraphicContent(types=types)
        assert sorted(type.value for type in graphic_content.types) == sorted(
            types
        )

    def test_graphic_content_pornographic_content(self):
        types = ["pornographic content"]
        graphic_content = GraphicContent(types=types)
        assert sorted(type.value for type in graphic_content.types) == sorted(
            types
        )

    def test_graphic_content_all_types_invalid(self):
        types = [
            "sexual content",
            "graphic content",
            "pornographic content",
            "invalid",
        ]
        with pytest.raises(ValueError):
            GraphicContent(types=types)
