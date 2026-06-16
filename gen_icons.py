from PIL import Image, ImageDraw, ImageFont

def make_icon(size, path):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = size // 5
    d.rounded_rectangle([0, 0, size-1, size-1], radius=r, fill="#0B1120")
    # Draw a simple device icon
    cx, cy = size // 2, size // 2
    pw, ph = int(size * 0.3), int(size * 0.5)
    br = size // 16
    d.rounded_rectangle([cx-pw, cy-ph, cx+pw, cy+ph], radius=br, outline="#2563EB", width=max(2, size//64))
    # Dot at bottom
    dr = max(2, size // 32)
    d.ellipse([cx-dr, cy+ph-dr*4, cx+dr, cy+ph-dr*2], fill="#2563EB")
    # "A" letter
    try:
        fs = int(size * 0.22)
        font = ImageFont.truetype("arial.ttf", fs)
    except:
        fs = int(size * 0.22)
        font = ImageFont.load_default()
    bb = d.textbbox((0,0), "A", font=font)
    tw, th = bb[2]-bb[0], bb[3]-bb[1]
    d.text((cx - tw//2, cy - th//2 - int(size*0.06)), "A", fill="#2563EB", font=font)
    img.save(path, "PNG")

make_icon(192, r"C:\src\argos_gateway\public\icon-192.png")
make_icon(512, r"C:\src\argos_gateway\public\icon-512.png")
print("Icons generated")
