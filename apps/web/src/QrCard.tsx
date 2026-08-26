import { qrSvg, qrSvgFromBytes } from "./qr";

export function QrCard({
  value,
  bytes,
  label,
}: {
  value?: string;
  bytes?: Uint8Array;
  label?: string;
}) {
  const svg = bytes ? qrSvgFromBytes(bytes, 4) : value ? qrSvg(value, 4) : "";
  if (!svg) return null;
  return (
    <div className="qr-card">
      {label ? <div className="hint">{label}</div> : null}
      <div className="qr" dangerouslySetInnerHTML={{ __html: svg }} />
      {value ? <div className="qr-uri">{value}</div> : null}
    </div>
  );
}
