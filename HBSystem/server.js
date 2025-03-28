import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

const db = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

app.use(cors());
app.use(express.json());

app.post("/register", async (req, res) => {
    try {
        console.log("Пришел запрос на регистрацию:", req.body);

        const { username, password, fullname, dob, email, phone } = req.body;
        if (!username || !password || !fullname || !dob || !email || !phone)
            return res.status(400).json({ message: "Заполните все поля" });

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            `INSERT INTO "Users" (username, password, fullname, dataofbirth, email, phone)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [username, hashedPassword, fullname, dob, email, phone]
        );

        res.json({ message: "Регистрация успешна" });
    } catch (error) {
        console.error("Ошибка при регистрации:", error);
        res.status(500).json({ message: "Ошибка сервера", error: error.message });
    }
});

app.listen(port, () => console.log(`Сервер запущен на http://localhost:${port}`));
