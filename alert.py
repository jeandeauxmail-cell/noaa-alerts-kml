import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# Constants
CAP_FEED_URL = "https://api.weather.gov/alerts/active.atom"
OUTPUT_KML = "alerts-overlay.kml"

# Severity-based styles
STYLES = {
    "Severe": {"color": "ff0000ff", "id": "severeStyle"},     # Red
    "Moderate": {"color": "ff00a5ff", "id": "moderateStyle"}, # Orange
    "Minor": {"color": "ff00ffff", "id": "minorStyle"},       # Yellow
}

def fetch_feed():
    response = requests.get(CAP_FEED_URL)
    response.raise_for_status()
    return ET.fromstring(response.content)

def extract_alerts(feed):
    ns = {
        "atom": "http://www.w3.org/2005/Atom",
        "cap": "urn:oasis:names:tc:emergency:cap:1.2"
    }
    alerts = []

    for entry in feed.findall("atom:entry", ns):
        # 1. Basic metadata
        title_elem = entry.find("atom:title", ns)
        title = title_elem.text if title_elem is not None else "Alert"

        # 2. Traverse into the CAP payload
        content = entry.find("atom:content", ns)
        if content is None:
            continue

        cap_alert = content.find("cap:alert", ns)
        if cap_alert is None:
            continue

        # 3. Loop through each <info> block
        for info in cap_alert.findall("cap:info", ns):
            severity_elem = info.find("cap:severity", ns)
            effective_elem = info.find("cap:effective", ns)
            expires_elem = info.find("cap:expires", ns)

            severity = severity_elem.text if severity_elem is not None else "Minor"
            effective = effective_elem.text if effective_elem is not None else ""
            expires = expires_elem.text if expires_elem is not None else ""

            # 4. Loop through each <area> block
            for area in info.findall("cap:area", ns):
                polygon = area.find("cap:polygon", ns)

                # 5. Skip if missing or empty
                if polygon is None or not polygon.text or not polygon.text.strip():
                    continue

                # 6. Build KML-ready coordinates
                raw_pts = polygon.text.strip().split()
                kml_coords = " ".join(
                    f"{lon},{lat},0"
                    for lat, lon in (pt.split(",") for pt in raw_pts)
                )

                alerts.append({
                    "title": title,
                    "severity": severity,
                    "effective": effective,
                    "expires": expires,
                    "coords": kml_coords
                })

    return alerts

def build_kml(alerts):
    kml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        '<Document>',
        '<name>Active Weather Alerts</name>'
    ]

    # Add styles
    for sev, style in STYLES.items():
        kml.append(f"""
        <Style id="{style['id']}">
            <PolyStyle>
                <color>{style['color']}</color>
                <fill>1</fill>
                <outline>1</outline>
            </PolyStyle>
        </Style>
        """)

    # Add Placemarks
    for alert in alerts:
        style_id = STYLES.get(alert["severity"], STYLES["Minor"])["id"]
        kml.append(f"""
        <Placemark>
            <name>{alert['title']}</name>
            <styleUrl>#{style_id}</styleUrl>
            <TimeSpan>
                <begin>{alert['effective']}</begin>
                <end>{alert['expires']}</end>
            </TimeSpan>
            <Polygon>
                <outerBoundaryIs>
                    <LinearRing>
                        <coordinates>{alert['coords']}</coordinates>
                    </LinearRing>
                </outerBoundaryIs>
            </Polygon>
        </Placemark>
        """)

    kml.append('</Document></kml>')
    return "\n".join(kml)

def main():
    feed = fetch_feed()
    alerts = extract_alerts(feed)
    kml_content = build_kml(alerts)
    Path(OUTPUT_KML).write_text(kml_content, encoding="utf-8")
    print(f"KML written to {OUTPUT_KML} with {len(alerts)} alerts.")

if __name__ == "__main__":
    main()
