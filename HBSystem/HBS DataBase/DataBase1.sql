PGDMP  :                    }            HBSystem    17.4    17.4 -    �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            �           1262    16388    HBSystem    DATABASE     p   CREATE DATABASE "HBSystem" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'ru-RU';
    DROP DATABASE "HBSystem";
                     postgres    false            �           0    0    DATABASE "HBSystem"    COMMENT     ~   COMMENT ON DATABASE "HBSystem" IS 'База данных на тему система бронирования отелей';
                        postgres    false    4852            �            1259    16424    Bookings    TABLE       CREATE TABLE public."Bookings" (
    booking_id integer NOT NULL,
    user_id integer NOT NULL,
    room_id integer NOT NULL,
    checkindate date,
    checkoutdate date,
    datecreated date,
    totalprice numeric(10,2) NOT NULL,
    paystatus character varying(15) NOT NULL
);
    DROP TABLE public."Bookings";
       public         heap r       postgres    false            �           0    0    TABLE "Bookings"    COMMENT     S   COMMENT ON TABLE public."Bookings" IS 'Забронированный номер';
          public               postgres    false    222            �            1259    16444    Bookings_discounts    TABLE     p   CREATE TABLE public."Bookings_discounts" (
    booking_id integer NOT NULL,
    discount_id integer NOT NULL
);
 (   DROP TABLE public."Bookings_discounts";
       public         heap r       postgres    false            �           0    0    TABLE "Bookings_discounts"    COMMENT     i   COMMENT ON TABLE public."Bookings_discounts" IS 'Связь скидок с бронированием';
          public               postgres    false    224            �            1259    16457    Bookings_services    TABLE     �   CREATE TABLE public."Bookings_services" (
    booking_id integer NOT NULL,
    service_id integer NOT NULL,
    quantity integer
);
 '   DROP TABLE public."Bookings_services";
       public         heap r       postgres    false            �           0    0    TABLE "Bookings_services"    COMMENT     p   COMMENT ON TABLE public."Bookings_services" IS 'Связь с дополнительными услушами';
          public               postgres    false    225            �            1259    16419 	   Discounts    TABLE     �   CREATE TABLE public."Discounts" (
    discount_id integer NOT NULL,
    code character varying(50) NOT NULL,
    type character varying(20) NOT NULL,
    value numeric(10,2) NOT NULL,
    datestart date,
    dateend date
);
    DROP TABLE public."Discounts";
       public         heap r       postgres    false            �           0    0    TABLE "Discounts"    COMMENT     ^   COMMENT ON TABLE public."Discounts" IS 'Скидки зависящие от времени';
          public               postgres    false    221            �            1259    16429    History    TABLE     �   CREATE TABLE public."History" (
    history_id integer NOT NULL,
    user_id integer NOT NULL,
    booking_id integer NOT NULL
);
    DROP TABLE public."History";
       public         heap r       postgres    false            �           0    0    TABLE "History"    COMMENT     P   COMMENT ON TABLE public."History" IS 'История бронирования';
          public               postgres    false    223            �            1259    16397    Hotels    TABLE     �   CREATE TABLE public."Hotels" (
    hotel_id integer NOT NULL,
    name character varying(100) NOT NULL,
    location character varying(200) NOT NULL,
    raiting numeric(3,2) NOT NULL
);
    DROP TABLE public."Hotels";
       public         heap r       postgres    false            �           0    0    TABLE "Hotels"    COMMENT     2   COMMENT ON TABLE public."Hotels" IS 'Отели';
          public               postgres    false    218            �            1259    16402    Rooms    TABLE     �   CREATE TABLE public."Rooms" (
    room_id integer NOT NULL,
    hotel_id integer NOT NULL,
    roomcount integer NOT NULL,
    price numeric(10,2),
    status character varying(15),
    fridge boolean,
    airconditioner boolean,
    balcony boolean
);
    DROP TABLE public."Rooms";
       public         heap r       postgres    false            �           0    0    TABLE "Rooms"    COMMENT     5   COMMENT ON TABLE public."Rooms" IS 'Комнаты';
          public               postgres    false    219            �            1259    16412    Services    TABLE     �   CREATE TABLE public."Services" (
    service_id integer NOT NULL,
    servicename character varying(100) NOT NULL,
    description text,
    price numeric(10,2)
);
    DROP TABLE public."Services";
       public         heap r       postgres    false            �           0    0    TABLE "Services"    COMMENT     e   COMMENT ON TABLE public."Services" IS 'Услуги (Спа, столик, бассейн и др)';
          public               postgres    false    220            �            1259    16392    Users    TABLE     ;  CREATE TABLE public."Users" (
    user_id integer NOT NULL,
    username character varying(50) NOT NULL,
    password character varying(100) NOT NULL,
    fullname character varying(100) NOT NULL,
    dataofbirth date NOT NULL,
    email character varying(100) NOT NULL,
    phone character varying(20) NOT NULL
);
    DROP TABLE public."Users";
       public         heap r       postgres    false            �          0    16424    Bookings 
   TABLE DATA           �   COPY public."Bookings" (booking_id, user_id, room_id, checkindate, checkoutdate, datecreated, totalprice, paystatus) FROM stdin;
    public               postgres    false    222   ^4       �          0    16444    Bookings_discounts 
   TABLE DATA           G   COPY public."Bookings_discounts" (booking_id, discount_id) FROM stdin;
    public               postgres    false    224   {4       �          0    16457    Bookings_services 
   TABLE DATA           O   COPY public."Bookings_services" (booking_id, service_id, quantity) FROM stdin;
    public               postgres    false    225   �4       �          0    16419 	   Discounts 
   TABLE DATA           Y   COPY public."Discounts" (discount_id, code, type, value, datestart, dateend) FROM stdin;
    public               postgres    false    221   �4       �          0    16429    History 
   TABLE DATA           D   COPY public."History" (history_id, user_id, booking_id) FROM stdin;
    public               postgres    false    223   �4       �          0    16397    Hotels 
   TABLE DATA           E   COPY public."Hotels" (hotel_id, name, location, raiting) FROM stdin;
    public               postgres    false    218   �4       �          0    16402    Rooms 
   TABLE DATA           o   COPY public."Rooms" (room_id, hotel_id, roomcount, price, status, fridge, airconditioner, balcony) FROM stdin;
    public               postgres    false    219   5       �          0    16412    Services 
   TABLE DATA           Q   COPY public."Services" (service_id, servicename, description, price) FROM stdin;
    public               postgres    false    220   )5       �          0    16392    Users 
   TABLE DATA           c   COPY public."Users" (user_id, username, password, fullname, dataofbirth, email, phone) FROM stdin;
    public               postgres    false    217   F5       K           2606    16428    Bookings Bookings_pkey 
   CONSTRAINT     `   ALTER TABLE ONLY public."Bookings"
    ADD CONSTRAINT "Bookings_pkey" PRIMARY KEY (booking_id);
 D   ALTER TABLE ONLY public."Bookings" DROP CONSTRAINT "Bookings_pkey";
       public                 postgres    false    222            I           2606    16423    Discounts Discounts_pkey 
   CONSTRAINT     c   ALTER TABLE ONLY public."Discounts"
    ADD CONSTRAINT "Discounts_pkey" PRIMARY KEY (discount_id);
 F   ALTER TABLE ONLY public."Discounts" DROP CONSTRAINT "Discounts_pkey";
       public                 postgres    false    221            M           2606    16433    History History_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public."History"
    ADD CONSTRAINT "History_pkey" PRIMARY KEY (history_id);
 B   ALTER TABLE ONLY public."History" DROP CONSTRAINT "History_pkey";
       public                 postgres    false    223            C           2606    16401    Hotels Hotels_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public."Hotels"
    ADD CONSTRAINT "Hotels_pkey" PRIMARY KEY (hotel_id);
 @   ALTER TABLE ONLY public."Hotels" DROP CONSTRAINT "Hotels_pkey";
       public                 postgres    false    218            E           2606    16406    Rooms Rooms_pkey 
   CONSTRAINT     W   ALTER TABLE ONLY public."Rooms"
    ADD CONSTRAINT "Rooms_pkey" PRIMARY KEY (room_id);
 >   ALTER TABLE ONLY public."Rooms" DROP CONSTRAINT "Rooms_pkey";
       public                 postgres    false    219            G           2606    16418    Services Services_pkey 
   CONSTRAINT     `   ALTER TABLE ONLY public."Services"
    ADD CONSTRAINT "Services_pkey" PRIMARY KEY (service_id);
 D   ALTER TABLE ONLY public."Services" DROP CONSTRAINT "Services_pkey";
       public                 postgres    false    220            A           2606    16396    Users Users_pkey 
   CONSTRAINT     W   ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_pkey" PRIMARY KEY (user_id);
 >   ALTER TABLE ONLY public."Users" DROP CONSTRAINT "Users_pkey";
       public                 postgres    false    217            O           2606    16439    History fk_booking_id    FK CONSTRAINT     �   ALTER TABLE ONLY public."History"
    ADD CONSTRAINT fk_booking_id FOREIGN KEY (booking_id) REFERENCES public."Bookings"(booking_id);
 A   ALTER TABLE ONLY public."History" DROP CONSTRAINT fk_booking_id;
       public               postgres    false    222    223    4683            Q           2606    16447     Bookings_discounts fk_booking_id    FK CONSTRAINT     �   ALTER TABLE ONLY public."Bookings_discounts"
    ADD CONSTRAINT fk_booking_id FOREIGN KEY (booking_id) REFERENCES public."Bookings"(booking_id);
 L   ALTER TABLE ONLY public."Bookings_discounts" DROP CONSTRAINT fk_booking_id;
       public               postgres    false    224    222    4683            S           2606    16460     Bookings_services fk_bookings_id    FK CONSTRAINT     �   ALTER TABLE ONLY public."Bookings_services"
    ADD CONSTRAINT fk_bookings_id FOREIGN KEY (booking_id) REFERENCES public."Bookings"(booking_id);
 L   ALTER TABLE ONLY public."Bookings_services" DROP CONSTRAINT fk_bookings_id;
       public               postgres    false    4683    222    225            R           2606    16452 !   Bookings_discounts fk_discount_id    FK CONSTRAINT     �   ALTER TABLE ONLY public."Bookings_discounts"
    ADD CONSTRAINT fk_discount_id FOREIGN KEY (discount_id) REFERENCES public."Discounts"(discount_id);
 M   ALTER TABLE ONLY public."Bookings_discounts" DROP CONSTRAINT fk_discount_id;
       public               postgres    false    221    224    4681            N           2606    16407    Rooms fk_hotel_id    FK CONSTRAINT     |   ALTER TABLE ONLY public."Rooms"
    ADD CONSTRAINT fk_hotel_id FOREIGN KEY (hotel_id) REFERENCES public."Hotels"(hotel_id);
 =   ALTER TABLE ONLY public."Rooms" DROP CONSTRAINT fk_hotel_id;
       public               postgres    false    218    219    4675            T           2606    16465    Bookings_services fk_service_id    FK CONSTRAINT     �   ALTER TABLE ONLY public."Bookings_services"
    ADD CONSTRAINT fk_service_id FOREIGN KEY (service_id) REFERENCES public."Services"(service_id);
 K   ALTER TABLE ONLY public."Bookings_services" DROP CONSTRAINT fk_service_id;
       public               postgres    false    225    220    4679            P           2606    16434    History fk_user_id    FK CONSTRAINT     z   ALTER TABLE ONLY public."History"
    ADD CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES public."Users"(user_id);
 >   ALTER TABLE ONLY public."History" DROP CONSTRAINT fk_user_id;
       public               postgres    false    223    4673    217            �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �     