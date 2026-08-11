from pathlib import Path
from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src" / "SmtpHeaderAnalyzer" / "Assets"
ASSETS.mkdir(parents=True, exist_ok=True)


def render(size: int) -> Image.Image:
    scale = size / 256
    image = Image.new("RGBA", (size, size), "#1B1E24")
    draw = ImageDraw.Draw(image)

    def box(values, **kwargs):
        draw.rounded_rectangle(tuple(int(v * scale) for v in values), radius=max(1, int(5 * scale)), **kwargs)

    white = "#F1F4F6"
    orange = "#FF982E"
    width = max(1, round(15 * scale))
    box((38, 54, 218, 194), outline=white, width=width)
    draw.line([(45 * scale, 66 * scale), (128 * scale, 136 * scale), (211 * scale, 66 * scale)], fill=white, width=width, joint="curve")
    draw.line([(48 * scale, 181 * scale), (99 * scale, 128 * scale)], fill=white, width=width)
    draw.line([(208 * scale, 181 * scale), (157 * scale, 128 * scale)], fill=white, width=width)

    route_width = max(1, round(11 * scale))
    draw.line([(69 * scale, 215 * scale), (113 * scale, 215 * scale), (143 * scale, 184 * scale), (189 * scale, 184 * scale)], fill=orange, width=route_width)
    radius = max(1, round(13 * scale))
    for x, y in ((69, 215), (189, 184)):
        draw.ellipse(((x * scale) - radius, (y * scale) - radius, (x * scale) + radius, (y * scale) + radius), fill=orange)
    return image


master = render(256)
master.save(ASSETS / "app-icon.png", optimize=True)
master.save(ASSETS / "app.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

qa = ROOT / "artifacts" / "qa"
qa.mkdir(parents=True, exist_ok=True)
preview = Image.new("RGBA", (256, 128), "#14171C")
preview.alpha_composite(render(16).resize((96, 96), Image.Resampling.NEAREST), (16, 16))
preview.alpha_composite(render(32).resize((96, 96), Image.Resampling.NEAREST), (144, 16))
preview.save(qa / "app-icon-16-32-preview.png", optimize=True)
