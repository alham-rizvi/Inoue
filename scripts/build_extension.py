"""Build Chrome and Firefox ZIP releases for the shared WebExtension."""

from pathlib import Path
import json
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "extension"
DIST = ROOT / "dist" / "extension"


def build(browser: str, manifest: dict) -> Path:
    archive = DIST / f"inoue-web-stack-detector-{browser}-{manifest['version']}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(SOURCE.iterdir()):
            if path.is_file():
                bundle.write(path, path.name)
    return archive


def main() -> None:
    manifest = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    archives = [build("chrome", manifest), build("firefox", manifest)]
    for archive in archives:
        print(archive.relative_to(ROOT))


if __name__ == "__main__":
    main()
