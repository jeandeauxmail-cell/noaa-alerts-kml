import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import html
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
CAP_FEED_URL = "https://api.weather.gov/alerts/active.atom"
OUTPUT_KML = "alerts-overlay.kml"
OUTPUT_DIR = "alerts"

# Enhanced severity-based styles with better color mapping
STYLES = {
    "Extreme": {"color": "ff0000cc", "id": "extremeStyle"},   # Dark Red
    "Severe": {"color": "ff0000ff", "id": "severeStyle"},     # Red
    "Moderate": {"color": "ff0066ff", "id": "moderateStyle"}, # Orange
    "Minor": {"color": "ff00ffff", "id": "minorStyle"},       # Yellow
    "Unknown": {"color": "ffcccccc", "id": "unknownStyle"},   # Gray
}

def fetch_feed():
    """Fetch the CAP feed with error handling and timeout."""
    try:
        logger.info(f"Fetching CAP feed from {CAP_FEED_URL}")
        response = requests.get(CAP_FEED_URL, timeout=30)
        response.raise_for_status()
        logger.info(f"Successfully fetched feed ({len(response.content)} bytes)")
        return ET.fromstring(response.content)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch CAP feed: {e}")
        raise
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML feed: {e}")
        raise

def extract_alerts(feed):
    """Extract alerts from the CAP feed with improved error handling."""
    ns = {
        "atom": "http://www.w3.org/2005/Atom",
        "cap": "urn:oasis:names:tc:emergency:cap:1.2"
    }
    alerts = []
    skipped_alerts = 0

    logger.info("Extracting alerts from feed")
    
    for entry in feed.findall("atom:entry", ns):
        try:
            # Basic metadata
            title_elem = entry.find("atom:title", ns)
            title = html.escape(title_elem.text if title_elem is not None else "Alert")
            
            # Get updated timestamp for better metadata
            updated_elem = entry.find("atom:updated", ns)
            updated = updated_elem.text if updated_elem is not None else ""

            # Traverse into the CAP payload
            content = entry.find("atom:content", ns)
            if content is None:
                skipped_alerts += 1
                continue

            cap_alert = content.find("cap:alert", ns)
            if cap_alert is None:
                skipped_alerts += 1
                continue

            # Loop through each <info> block
            for info in cap_alert.findall("cap:info", ns):
                severity_elem = info.find("cap:severity", ns)
                effective_elem = info.find("cap:effective", ns)
                expires_elem = info.find("cap:expires", ns)
                event_elem = info.find("cap:event", ns)
                description_elem = info.find("cap:description", ns)

                severity = severity_elem.text if severity_elem is not None else "Unknown"
                effective = effective_elem.text if effective_elem is not None else ""
                expires = expires_elem.text if expires_elem is not None else ""
                event = event_elem.text if event_elem is not None else ""
                description = description_elem.text if description_elem is not None else ""

                # Loop through each <area> block
                for area in info.findall("cap:area", ns):
                    area_desc_elem = area.find("cap:areaDesc", ns)
                    area_desc = area_desc_elem.text if area_desc_elem is not None else ""
                    
                    polygon = area.find("cap:polygon", ns)

                    # Skip if missing or empty polygon
                    if polygon is None or not polygon.text or not polygon.text.strip():
                        continue

                    # Validate and build KML-ready coordinates
                    try:
                        raw_pts = polygon.text.strip().split()
                        if len(raw_pts) < 3:  # Need at least 3 points for a polygon
                            continue
                            
                        kml_coords_list = []
                        for pt in raw_pts:
                            if ',' not in pt:
                                continue
                            lat, lon = pt.split(",", 1)
                            # Validate coordinates
                            try:
                                lat_float = float(lat)
                                lon_float = float(lon)
                                if -90 <= lat_float <= 90 and -180 <= lon_float <= 180:
                                    kml_coords_list.append(f"{lon},{lat},0")
                            except ValueError:
                                continue
                        
                        if len(kml_coords_list) < 3:
                            continue
                            
                        kml_coords = " ".join(kml_coords_list)
                        
                        # Ensure polygon is closed
                        if kml_coords_list[0] != kml_coords_list[-1]:
                            kml_coords += f" {kml_coords_list[0]}"

                        alerts.append({
                            "title": title,
                            "severity": severity,
                            "effective": effective,
                            "expires": expires,
                            "coords": kml_coords,
                            "event": event,
                            "description": html.escape(description[:500] + "..." if len(description) > 500 else description),
                            "area": html.escape(area_desc),
                            "updated": updated
                        })
                        
                    except Exception as e:
                        logger.warning(f"Error processing polygon for alert '{title}': {e}")
                        continue

        except Exception as e:
            logger.warning(f"Error processing alert entry: {e}")
            skipped_alerts += 1
            continue

    logger.info(f"Extracted {len(alerts)} alerts, skipped {skipped_alerts}")
    return alerts

def build_kml(alerts):
    """Build KML content with enhanced metadata and error handling."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    kml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        '<Document>',
        f'<name>Active Weather Alerts - Generated {timestamp}</name>',
        f'<description>Weather alerts from NOAA/NWS. Generated: {timestamp}</description>'
    ]

    # Add styles
    for sev, style in STYLES.items():
        kml.append(f'''
        <Style id="{style['id']}">
            <PolyStyle>
                <color>{style['color']}</color>
                <fill>1</fill>
                <outline>1</outline>
            </PolyStyle>
            <LabelStyle>
                <scale>0.8</scale>
            </LabelStyle>
        </Style>''')

    # Group alerts by severity for better organization
    severity_counts = {}
    for alert in alerts:
        severity = alert["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Add folders for each severity level
    for severity in ["Extreme", "Severe", "Moderate", "Minor", "Unknown"]:
        if severity in severity_counts:
            kml.append(f'<Folder><name>{severity} ({severity_counts[severity]})</name>')
            
            # Add placemarks for this severity
            for alert in alerts:
                if alert["severity"] == severity:
                    style_id = STYLES.get(alert["severity"], STYLES["Unknown"])["id"]
                    
                    # Build description with available metadata
                    desc_parts = []
                    if alert["event"]:
                        desc_parts.append(f"Event: {alert['event']}")
                    if alert["area"]:
                        desc_parts.append(f"Area: {alert['area']}")
                    if alert["effective"]:
                        desc_parts.append(f"Effective: {alert['effective']}")
                    if alert["expires"]:
                        desc_parts.append(f"Expires: {alert['expires']}")
                    if alert["description"]:
                        desc_parts.append(f"Description: {alert['description']}")
                    
                    description = "<br/>".join(desc_parts)
                    
                    placemark = f'''
        <Placemark>
            <name>{alert['title']}</name>
            <description><![CDATA[{description}]]></description>
            <styleUrl>#{style_id}</styleUrl>'''
            
                    # Add time span if available
                    if alert["effective"] and alert["expires"]:
                        placemark += f'''
            <TimeSpan>
                <begin>{alert['effective']}</begin>
                <end>{alert['expires']}</end>
            </TimeSpan>'''
            
                    placemark += f'''
            <Polygon>
                <outerBoundaryIs>
                    <LinearRing>
                        <coordinates>{alert['coords']}</coordinates>
                    </LinearRing>
                </outerBoundaryIs>
            </Polygon>
        </Placemark>'''
                    
                    kml.append(placemark)
            
            kml.append('</Folder>')

    kml.append('</Document>')
    kml.append('</kml>')
    return "\n".join(kml)

def ensure_output_directory():
    """Ensure the output directory exists."""
    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(exist_ok=True)
    return output_path

def main():
    """Main execution function with comprehensive error handling."""
    try:
        # Ensure output directory exists
        output_path = ensure_output_directory()
        output_file = output_path / OUTPUT_KML
        
        # Fetch and process data
        feed = fetch_feed()
        alerts = extract_alerts(feed)
        
        if not alerts:
            logger.warning("No alerts found in feed")
            # Create empty KML file
            empty_kml = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<name>Active Weather Alerts - No Active Alerts</name>
<description>No active weather alerts at this time.</description>
</Document>
</kml>'''
            output_file.write_text(empty_kml, encoding="utf-8")
            logger.info(f"Empty KML written to {output_file}")
            return
        
        # Build and write KML
        kml_content = build_kml(alerts)
        output_file.write_text(kml_content, encoding="utf-8")
        
        # Log summary
        severity_summary = {}
        for alert in alerts:
            sev = alert["severity"]
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
        
        logger.info(f"KML written to {output_file} with {len(alerts)} alerts")
        for sev, count in severity_summary.items():
            logger.info(f"  {sev}: {count} alerts")
            
    except Exception as e:
        logger.error(f"Script failed: {e}")
        raise

if __name__ == "__main__":
    main()
