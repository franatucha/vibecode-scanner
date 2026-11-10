import OpenAI from "openai";
import { auth } from "@/lib/auth";
import { ratelimit } from "@/lib/ratelimit";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { success } = await ratelimit.limit(session.user.id);
  if (!success) return new Response("Too many requests", { status: 429 });
  const { text } = await req.json();
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: text }] });
  return Response.json(r.choices[0].message);
}
