import express from 'express';
import pg from 'pg';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// Определение __dirname в ES-модулях
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Подключение к PostgreSQL
const { Pool } = pg;
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'hotel_booking',
    password: process.env.DB_PASSWORD || '1234',
    port: process.env.DB_PORT || 5432,
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }));

// Раздача статических файлов (HTML, CSS, изображения)
app.use(express.static(path.join(__dirname, 'public')));

// Проверка подключения к БД
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Ошибка подключения к PostgreSQL:', err);
    }
    console.log('✅ Успешное подключение к PostgreSQL');
    release();
});

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html')); // Можно поменять на index.html
});

// Роут для регистрации
app.post('/api/register', async (req, res) => {
    try {
        const { fullname, phone, dob, email, username, password } = req.body;

        // Валидация данных
        if (!fullname || !phone || !dob || !email || !username || !password) {
            return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
        }

        // Проверка существования пользователя
        const userExists = await pool.query(
            `SELECT * FROM public."Users" WHERE email = $1 OR username = $2`,
            [email, username]
        );

        if (userExists.rows.length > 0) {
            return res.status(409).json({ error: 'Пользователь с таким email или логином уже существует' });
        }

        // Добавление нового пользователя
        const newUser = await pool.query(
            `INSERT INTO public."Users" 
             (user_id, username, password, fullname, dataofbirth, email, phone) 
             VALUES (nextval('users_user_id_seq'), $1, $2, $3, $4, $5, $6) 
             RETURNING user_id, username, email, fullname`,
            [username, password, fullname, dob, email, phone]
        );

        res.status(201).json({
            success: true,
            user: newUser.rows[0],
            message: 'Пользователь успешно зарегистрирован'
        });

    } catch (err) {
        console.error('Ошибка регистрации:', err);
        res.status(500).json({ 
            error: 'Ошибка сервера при регистрации',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Обработка 404
app.use((req, res) => {
    res.status(404).json({ error: 'Не найдено' });
});

// Запуск сервера
app.listen(port, () => {
    console.log(`🚀 Сервер запущен на http://localhost:${port}`);
    console.log(`🔧 Режим работы: ${process.env.NODE_ENV || 'development'}`);
});

// Закрытие соединения с БД при завершении работы
process.on('SIGTERM', () => {
    pool.end(() => {
        console.log('⛔ Пул PostgreSQL отключен');
        process.exit(0);
    });
});
