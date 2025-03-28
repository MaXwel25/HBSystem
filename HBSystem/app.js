const { createApp } = Vue;

const app = createApp({
    data() {
        return {
            isModalVisible: false,
            currentHotelIndex: 0,
            hotels: [
                {
                    id: 1,
                    name: 'Москва',
                    images: ['media/hotel1.jpg', 'media/hotel2.jpg'],
                    description: 'Отель в центре Москвы с прекрасным видом на Кремль.',
                    rooms: [
                        { type: 'Люкс', price: 10000 },
                        { type: 'Эконом', price: 5000 }
                    ]
                },
                {
                    id: 2,
                    name: 'Санкт-Петербург',
                    images: ['media/hotel3.jpg', 'media/hotel4.jpg'],
                    description: 'Отель в историческом центре Санкт-Петербурга.',
                    rooms: [
                        { type: 'Люкс', price: 12000 },
                        { type: 'Эконом', price: 6000 }
                    ]
                },
                {
                    id: 3,
                    name: 'Краснодар',
                    images: ['media/hotel5.jpg', 'media/hotel6.jpg'],
                    description: 'Отель в центре Краснодара с современным дизайном.',
                    rooms: [
                        { type: 'Люкс', price: 8000 },
                        { type: 'Эконом', price: 4000 }
                    ]
                }
            ],
            slideDirection: 'slide-left'
        };
    },
    methods: {
        showModal() {
            this.isModalVisible = true;
        },
        closeModal() {
            this.isModalVisible = false;
        },
        goToRegister() {
            window.location.href = 'register.html';
        },
        goToLogin() {
            window.location.href = 'login.html';
        },
        prevHotel() {
            if (this.currentHotelIndex > 0) {
                this.currentHotelIndex--;
            }
        },
        nextHotel() {
            if (this.currentHotelIndex < this.hotels.length - 1) {
                this.currentHotelIndex++;
            }
        }
    },
    watch: {
        currentHotelIndex(newIndex, oldIndex) {
            this.slideDirection = newIndex > oldIndex ? 'slide-left' : 'slide-right';
        }
    }
});

app.mount('body');
