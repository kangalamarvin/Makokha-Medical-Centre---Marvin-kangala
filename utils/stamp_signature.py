"""
Digital Stamp and Signature Generator
Generates dynamic, date-stamped official stamps and loads hand-drawn signatures
"""
from datetime import datetime, timedelta, timezone
from markupsafe import Markup
import os


def _eat_now() -> datetime:
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("Africa/Nairobi"))
    except Exception:
        return datetime.now(timezone(timedelta(hours=3)))


def _env_float(name: str, default: float) -> float:
    try:
        val = os.getenv(name)
        if val is None or str(val).strip() == '':
            return float(default)
        return float(val)
    except Exception:
        return float(default)


def get_stamp_typography() -> dict:
    """Central stamp typography defaults.

    Used by both SVG (HTML receipts/documents) and ReportLab PDF stamps.
    Values can be overridden via environment variables without code changes.
    """
    stamp_color = os.getenv('STAMP_COLOR', '#2e3192')
    date_color = os.getenv('STAMP_DATE_COLOR', '#dc143c')

    svg_font_bold = os.getenv(
        'STAMP_SVG_FONT_BOLD',
        'Arial Black, Arial, Helvetica, sans-serif',
    )
    svg_font_regular = os.getenv(
        'STAMP_SVG_FONT_REGULAR',
        'Arial, Helvetica, sans-serif',
    )

    # ReportLab built-in fonts (safe defaults).
    pdf_font_bold = os.getenv('STAMP_PDF_FONT_BOLD', 'Helvetica-Bold')
    pdf_font_regular = os.getenv('STAMP_PDF_FONT_REGULAR', 'Helvetica')

    return {
        'colors': {
            'stamp': stamp_color,
            'date': date_color,
        },
        'svg': {
            'font_bold': svg_font_bold,
            'font_regular': svg_font_regular,
        },
        'pdf': {
            'font_bold': pdf_font_bold,
            'font_regular': pdf_font_regular,
            # Point sizes tuned for ~80mm receipt PDFs.
            'size_title': _env_float('STAMP_PDF_SIZE_TITLE', 7.0),
            'size_date': _env_float('STAMP_PDF_SIZE_DATE', 8.0),
            'size_contact': _env_float('STAMP_PDF_SIZE_CONTACT', 6.5),
            'line_width': _env_float('STAMP_PDF_LINE_WIDTH', 1.2),
        },
    }


def get_stamp_pdf_style() -> dict:
    """Back-compat helper for PDF stamp drawing."""
    return get_stamp_typography().get('pdf', {})

def generate_rubber_stamp(facility_name="MAKOKHA MEDICAL CENTRE", 
                          email="makokhamedicalcentre2025@gmail.com",
                          phone1="0741 256 531",
                          phone2="0713 580 997",
                          current_date=None,
                          stamp_color="#2e3192",
                          size=230):
    """
    Generate SVG for a rectangular rubber stamp matching the provided image
    
    Args:
        facility_name: Name of the facility (default: MAKOKHA MEDICAL CENTRE)
        email: Email address
        phone1: First phone number
        phone2: Second phone number
        current_date: Date to display (default: today in format "21 DEC 2025")
        stamp_color: Color of stamp (default: blue #2e3192)
        size: Width in pixels (default: 230 for receipts)
    
    Returns:
        Markup: Safe HTML/SVG for rubber stamp
    """
    if current_date is None:
        # Format: "21 DEC 2025"
        current_date = _eat_now().strftime('%d %b %Y').upper()

    typo = get_stamp_typography()
    svg_bold = typo['svg']['font_bold']
    svg_regular = typo['svg']['font_regular']
    if not stamp_color:
        stamp_color = typo['colors']['stamp']
    date_color = typo['colors']['date']
    
    # Calculate proportional dimensions (matching the rectangular stamp image)
    width = float(size)
    height = width * 0.55  # Rectangular ratio

    # Typography calibration
    # SVG uses user units that are scaled by viewBox -> rendered px. We compute font sizes
    # from desired point sizes so printed output matches the target ranges more closely.
    # Assumes typical browser print scaling (1 CSS px = 1/96 in, 1 pt = 1/72 in).
    viewbox_w = 400.0
    scale = max(width / viewbox_w, 1e-6)
    stamp_width_mm = max(1e-6, (width * 25.4) / 96.0)

    def _pt_to_px(pt: float) -> float:
        return float(pt) * (96.0 / 72.0)

    # Targets when printed on receipts:
    # - Clinic name must stay comfortably inside inner border
    # - Date should sit closer to title (reduced gap)
    # - Labels (email/phones): 7–8pt equivalent
    title_fs = _pt_to_px(9.8) / scale
    date_fs = _pt_to_px(8.75) / scale
    contact_fs = _pt_to_px(7.5) / scale

    facility_text = ' '.join((facility_name or '').split())
    if not facility_text:
        facility_text = 'MAKOKHA MEDICAL CENTRE'
    if len(facility_text) > 24:
        title_fs *= 0.92
    if len(facility_text) > 30:
        title_fs *= 0.88

    # Keep title text at least ~0.15 cm from the inner border on both sides.
    # Convert to viewBox units so this stays proportional across stamp sizes.
    title_side_margin_units = max(4.0, (1.5 / stamp_width_mm) * viewbox_w)
    title_box_w = max(120.0, 376.0 - (2.0 * title_side_margin_units))
    # Extra fit guard so title text never presses against the safe box.
    # Approximate uppercase glyph width around 0.62*font-size.
    est_title_w = max(1.0, len(facility_text) * (title_fs * 0.62 + 0.35))
    if est_title_w > title_box_w:
        title_fs *= (title_box_w / est_title_w)
    title_fs = max(title_fs, 14.5)
    
    stamp_svg = f"""
    <svg width="{width}" height="{height}" viewBox="0 0 400 220" xmlns="http://www.w3.org/2000/svg" style="background: transparent; display: block; margin-left: -0.8cm;">
        <!-- Outer border -->
        <rect x="5" y="5" width="390" height="210" 
              fill="none" 
              stroke="{stamp_color}" 
              stroke-width="6" 
              rx="3"/>
        
        <!-- Inner border -->
        <rect x="12" y="12" width="376" height="196" 
              fill="none" 
              stroke="{stamp_color}" 
              stroke-width="2" 
              rx="2"/>
        
        <!-- Facility name (top, single-line, fitted to inner border) -->
          <text x="200" y="58" 
              font-family="{svg_bold}" 
                            font-size="{title_fs:.2f}" 
              font-weight="900" 
              fill="{stamp_color}" 
              text-anchor="middle"
              letter-spacing="0.4">
            {facility_text}
        </text>
        
        <!-- Left star -->
        <polygon points="50,86 53,94 62,94 55,100 58,108 50,103 42,108 45,100 38,94 47,94" 
                 fill="{stamp_color}"/>
        
          <!-- Date (center, in red, closer to facility name) -->
        <text x="200" y="102" 
              font-family="{svg_bold}" 
              font-size="{date_fs:.2f}" 
              font-weight="900" 
              fill="{date_color}" 
              text-anchor="middle"
              letter-spacing="1">
            {current_date}
        </text>
        
        <!-- Right star -->
        <polygon points="350,86 353,94 362,94 355,100 358,108 350,103 342,108 345,100 338,94 347,94" 
                 fill="{stamp_color}"/>
        
          <!-- Email -->
        <text x="200" y="145" 
              font-family="{svg_regular}" 
              font-size="{contact_fs:.2f}" 
              font-weight="bold" 
              fill="{stamp_color}" 
              text-anchor="middle">
            {email}
        </text>
        
          <!-- Phone numbers -->
        <text x="200" y="170" 
              font-family="{svg_regular}" 
              font-size="{contact_fs:.2f}" 
              font-weight="bold" 
              fill="{stamp_color}" 
              text-anchor="middle">
            Tel: {phone1} / {phone2}
        </text>
    </svg>
    """
    
    return Markup(stamp_svg)


def generate_digital_signature(signer_name="Makokha",
                               signer_title="Medical Director",
                               signature_date=None,
                               include_date=True,
                               user_id=None):
    """
    Load hand-drawn signature from database or show placeholder
    
    This function is now a placeholder that tells templates to use the signature_pad component.
    The actual signature rendering happens client-side via JavaScript.
    
    Args:
        signer_name: Name of person signing (default: Makokha)
        signer_title: Title/position of signer  
        signature_date: Date of signature (default: today)
        include_date: Whether to show signature date
        user_id: User ID to load signature for (optional)
    
    Returns:
        Markup: HTML comment indicating signature pad should be used
    """
    if signature_date is None:
        signature_date = _eat_now().strftime('%d %B %Y')
    
    # Return a marker that indicates signature pad component should be included
    # The actual rendering is handled by the signature_pad.html template
    signature_html = f"""
    <!-- SIGNATURE_PAD: title="{signer_title}" date="{signature_date}" -->
    <div class="signature-container" data-signer-title="{signer_title}" data-signature-date="{signature_date}">
        <!-- Signature will be loaded here by signature_pad.html component -->
    </div>
    """
    
    return Markup(signature_html)


def get_current_stamp_date():
    """Get current date formatted for stamp"""
    return _eat_now().strftime('%d %b %Y')


def get_current_signature_date():
    """Get current date formatted for signature"""
    return _eat_now().strftime('%d %B %Y')
