import { pool } from "@/lib/db";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = ${params.id}`);
  return Response.json(rows[0]);
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await pool.query("DELETE FROM users WHERE id = " + params.id);
  return new Response(null, { status: 204 });
}
