import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

app.post("/api/orders", async (req, res) => {
  res.json({ ok: true, order: req.body });
});

app.listen(3001);
