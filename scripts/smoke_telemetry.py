"""Installation metadata for package smoke homes."""

from pathlib import Path
import shutil


def prepare_installation(home):
    installation = home / ".strands/box/installation.toml"
    installation.parent.mkdir(parents=True)
    original = Path.home() / ".strands/box/installation.toml"
    if original.exists():
        shutil.copyfile(original, installation, follow_symlinks=False)
    else:
        installation.write_text('installation_id = ""\n')
