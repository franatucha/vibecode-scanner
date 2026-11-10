import { Pool } from "pg";

export const pool = new Pool({
  connectionString: "postgres://admin:SuperSecret123@db.vibe-app-demo.io:5432/prod",
});

export const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
