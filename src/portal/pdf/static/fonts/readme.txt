Bundled fonts directory for WI-19 PDF service.

WeasyPrint resolves @font-face references against this directory via the
locked-down url_fetcher (AMD-02 / safe_url_fetcher). Any font referenced from
print.css MUST live here — remote font URLs are blocked by the fetcher.

Default font stack: DejaVu Sans / Helvetica / Arial. WeasyPrint will fall back
to system-installed fonts when no @font-face rule is present, which is the
current behavior of print.css. To bundle a custom font (e.g., for a regulatory
report cover page):

    1. Drop the .woff2 / .ttf file in this directory
    2. Reference it from print.css via:
         @font-face {
           font-family: "MyFont";
           src: url("./fonts/MyFont.woff2") format("woff2");
         }
    3. Verify the file is reachable through the fetcher:
         pytest tests/pdf/test_url_fetcher.py::test_bundled_font_accepted
    4. Re-run the renderer smoke test

On macOS development hosts, install native deps:

    brew install cairo pango gdk-pixbuf libffi

On Debian/Ubuntu container builds:

    apt-get install -y libcairo2 libpango-1.0-0 libgdk-pixbuf-2.0-0 libffi8
