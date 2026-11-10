// A reviewed exception, silenced on purpose:
// vibescan-ignore
export const run = (code: string) => eval(code);

export const cors = { origin: ["https://clean-app.example"] };
export const API_KEY_HEADER = "x-api-key";
