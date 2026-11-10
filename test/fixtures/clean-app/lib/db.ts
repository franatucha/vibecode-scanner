import postgres from "postgres";
export const sql = postgres(process.env.DATABASE_URL!);

export const findPost = (id: string) => sql`SELECT * FROM posts WHERE id = ${id}`;
export const deletePost = (db: { query: Function }, id: string) => db.query("DELETE FROM posts WHERE id = $1", [id]);
