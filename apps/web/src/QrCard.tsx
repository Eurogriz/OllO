import { qrSvg } from "./qr";

export function QrCard({ value, label }: { value: string; label?: string }) {
  if (!value) return null;
  const svg = qrSvg(value, 4);
  return (
    <div className="qr-card">
      {label ? <div className="hint">{label}</div> : null}
      <div className="qr" dangerouslySetInnerHTML={{ __html: svg }} />
      <div className="qr-uri">{value}</div>
    </div>
  );
}
