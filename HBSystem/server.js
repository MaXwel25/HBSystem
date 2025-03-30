import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = "1234";

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
        res.status(500).json({ message: "Ошибка сервера", error: error.message });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ message: "Заполните все поля" });

        const user = await db.query(
            `SELECT * FROM "Users" WHERE username = $1 OR email = $1`,
            [username]
        );

        console.log("Найденный пользователь:", user.rows[0]);

        if (user.rows.length === 0)
            return res.status(401).json({ message: "Неверные учетные данные" });

        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        console.log("Результат сравнения пароля:", validPassword);

        if (!validPassword)
            return res.status(401).json({ message: "Неверные учетные данные" });

        const token = jwt.sign({ id: user.rows[0].user_id }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token, user: { username: user.rows[0].username, email: user.rows[0].email } });
    } catch (error) {
        res.status(500).json({ message: "Ошибка сервера", error: error.message });
    }
});

app.get("/profile", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ message: "Нет токена" });
        
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        
        const user = await db.query(
            `SELECT fullname, dataofbirth, email, phone FROM "Users" WHERE user_id = $1`,
            [decoded.id]
        );
        
        if (user.rows.length === 0)
            return res.status(404).json({ message: "Пользователь не найден" });
        
        res.json(user.rows[0]);
    } catch (error) {
        res.status(401).json({ message: "Ошибка авторизации", error: error.message });
    }
});

app.listen(port, () => console.log(`Сервер запущен на http://localhost:${port}`));
