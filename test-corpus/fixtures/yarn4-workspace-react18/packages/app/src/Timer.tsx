import { useEffect, useRef, useState } from "react";

export function Timer(): JSX.Element {
  const [ticks, setTicks] = useState(0);
  const handle = useRef<number>();
  useEffect(() => {
    handle.current = window.setInterval(() => setTicks((t) => t + 1), 1000);
    return () => window.clearInterval(handle.current);
  }, []);
  return <span>{ticks}</span>;
}
