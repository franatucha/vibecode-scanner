"use client";
import OpenAI from "openai";
import { useState } from "react";

const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export function ChatBox() {
  const [answer, setAnswer] = useState("");
  async function ask(q: string) {
    const r = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: q }] });
    setAnswer(r.choices[0].message.content ?? "");
  }
  return <div onClick={() => ask("hi")}>{answer}</div>;
}
