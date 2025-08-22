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
        area = entry.find("cap:areaDesc", ns)
        polygon = entry.find("cap:polygon", ns)
        severity = entry.find("cap:severity", ns)
        effective = entry.find("cap:effective", ns)
        expires = entry.find("cap:expires", ns)
        title = entry.find("atom:title", ns)

        if polygon is not None:
            coords = polygon.text.strip().split(" ")
            kml_coords = " ".join([f"{lon},{lat},0" for lat, lon in (pt.split(",") for pt in coords)])
            alerts.append({
                "title": title.text if title is not None else "Alert",
                "severity": severity.text if severity is not None else "Minor",
                "effective": effective.text if effective is not None else "",
                "expires": expires.text if expires is not None else "",
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
