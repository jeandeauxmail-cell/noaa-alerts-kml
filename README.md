# NOAA Alerts KML (Live)

This repository periodically fetches the **nationwide CAP alert feed** (`https://alerts.weather.gov/cap/us.php?x=1`)
and converts it to a live-updating KML file containing alert polygons.

### 🔄 How It Works

- GitHub Actions runs every **5 minutes**
- `generate_kml.py` fetches the CAP feed and converts it to `noaa_alerts.kml`
- The resulting KML is committed to the **gh-pages** branch

### 🌐 GitHub Pages

After the first run, enable **GitHub Pages** on the `gh-pages` branch.

Your live KML will then be accessible at:

