"""This script is intended to be used at build-time. It pre-renders configurable static components e.g.
version, branding images. Refer to function docstrings for more details."""

import os

from jinja2 import Environment, FileSystemLoader

templates = Environment(loader=FileSystemLoader("templates"))


# TODO: Formalise versioning across components + client vs. server testing
def base_template() -> None:
    """Modifies the base.html template with following context:
    - Injects images (.webp) into hosted by section of the base page's footer.
    NOTE: All (.webp) images under './static/base/' path will be included.
    - sets platform version from CACTUS_PLATFORM_VERSION envvar
    """
    base_path = os.path.join(app.static_folder, "base")  # type: ignore
    webp_images = [f"base/{f}" for f in os.listdir(base_path) if f.endswith(".webp")]
    ctxt = {"hosted_images": webp_images, "version": os.environ["CACTUS_PLATFORM_VERSION"]}

    template = templates.get_template("base.html")
    with open("dist/base.html", "w") as f:
        f.write(template.render(**ctxt))


def home_template() -> None:
    """Modifies the home.html template with the following context:
    - Adds support email from SUPPORT_EMAIL envvar."""
    ctxt = {"support_email": os.environ["SUPPORT_EMAIL"]}

    template = templates.get_template("home.html")
    with open("dist/home.html", "w") as f:
        f.write(template.render(**ctxt))


if __name__ == "__main__":
    base_template()
    home_template
