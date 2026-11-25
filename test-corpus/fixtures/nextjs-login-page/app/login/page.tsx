"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get("email") === "demo@example.com" && form.get("password") === "secret") {
      router.push("/welcome");
    } else {
      setError("Wrong email or password");
    }
  }

  return (
    <form onSubmit={submit}>
      <label>
        Email <input name="email" type="email" />
      </label>
      <label>
        Password <input name="password" type="password" />
      </label>
      <button type="submit">Sign in</button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
