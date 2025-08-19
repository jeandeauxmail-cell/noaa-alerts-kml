#!/usr/bin/env python3
"""
Fetches the nationwide NWS CAP feed and converts current alerts into a KML file.
Only the event, headline, onset, and expires fields are included in the placemark
description.
"""

import requests
import xml.etree.ElementTree as ET
from datetime import datetime

CAP_FEED_URL = "https://alerts.weather.gov/cap/us.php?x=1"
OUTPUT_KML = "noaa_alerts.kml"

def parse_cap_feed(url):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    ns = {"cap": "urn:oasis:names:tc:emergency:cap:1.1", "atom": "http://www.w3.org/2005/Atom"}
    root = ET.fromstring(resp.content)

    alerts = []
    for entry in root.findall("atom:entry", ns):
        # Each entry is a CAP alert
        polygon = entry.findtext("cap:polygon", default="", namespaces=ns)
        event = entry.findtext("cap:event", default="")
        headline = entry.findtext("cap:headline", default="")
        onset = entry.findtext("cap:onset", default="")
        expires = entry.findtext("cap:expires", default="")

        if not polygon:
            continue  # skip if no polygon

        alerts.append({
            "polygon": polygon,
            "event": event,
            "headline": headline,
            "onset": onset,
            "expires": expires
        })
    return alerts

def polygon_to_coordinates(polygon_str):
    # CAP polygon is space-separated "lat,lon lat,lon ..."
    coords = []
    for point in polygon_str.strip().split():
        lat, lon = point.split(",")
        coords.append(f"{lon},{lat},0")
    return " ".join(coords)

def build_kml(alerts):
    kml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        "<Document>"
    ]
    timestamp = datetime.utcnow().isoformat() + "Z"
    kml_parts.append(f"<name>NOAA Alerts (updated {timestamp})</name>")

    for alert in alerts:
        coords = polygon_to_coordinates(alert["polygon"])
        kml_parts.append("<Placemark>")
        kml_parts.append(f"<name>{alert['event']}</name>")
        description = (f"<![CDATA[<b>Headline:</b> {alert['headline']}<br>"
                       f"<b>Onset:</b> {alert['onset']}<br>"
                       f"<b>Expires:</b> {alert['expires']}"
                       "]]>")
        kml_parts.append(f"<description>{description}</description>")
        kml_parts.append("<Polygon><outerBoundaryIs><LinearRing>")
        kml_parts.append(f"<coordinates>{coords}</coordinates>")
        kml_parts.append("</LinearRing></outerBoundaryIs></Polygon>")
        kml_parts.append("</Placemark>")

    kml_parts.append("</Document></kml>")
    return "\n".join(kml_parts)

def main():
    alerts = parse_cap_feed(CAP_FEED_URL)
    kml = build_kml(alerts)
    with open(OUTPUT_KML, "w", encoding="utf-8") as f:
        f.write(kml)
    print(f"Wrote {OUTPUT_KML} with {len(alerts)} alerts.")

if __name__ == "__main__":
    main()
