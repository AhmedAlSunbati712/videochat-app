import cv2
import math

def capture_compressed_photo_bytes(
    camera_index=1,
    max_width=800,
    max_height=800,
    jpeg_quality=70,  # 0–100, higher = better quality, bigger file
):
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        raise RuntimeError("Could not open camera")

    # Warmup
    for _ in range(5):
        cap.read()

    ret, frame = cap.read()
    cap.release()

    if not ret:
        raise RuntimeError("Failed to capture image")

    # --- 1) Resize to fit within max_width x max_height ---
    h, w = frame.shape[:2]
    scale = min(max_width / w, max_height / h, 1.0)  # never upscale
    if scale < 1.0:
        new_w = int(w * scale)
        new_h = int(h * scale)
        frame = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)

    # --- 2) Encode as lower-quality JPEG ---
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), int(jpeg_quality)]
    success, buffer = cv2.imencode(".jpg", frame, encode_params)
    if not success:
        raise RuntimeError("Failed to encode image")

    img_bytes = buffer.tobytes()
    return img_bytes


if __name__ == "__main__":
    photo_bytes = capture_compressed_photo_bytes(
        camera_index=1,
        max_width=400,
        max_height=400,
        jpeg_quality=65,
    )
    print(f"Compressed image size: {len(photo_bytes)} bytes")


    image_size = len(photo_bytes)
    frames_to_print = math.ceil(image_size / 1400)
    print(frames_to_print)
    
    for i in range(frames_to_print):
        frame_bytes = photo_bytes[i*1400:(i+1)*1400]

        with open(f"photo{i}.jpg", "wb") as f:
            f.write(frame_bytes)

