class CaesarCipher:
    def __init__(self):
        self.characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?."
        self.char_length = len(self.characters)

    def decrypt(self, message: str, key: int) -> str:
        """Расшифровывает сообщение с использованием заданного ключа."""
        decrypted_message = ''
        for char in message:
            if char in self.characters:
                index = (self.characters.index(char) - key) % self.char_length
                decrypted_message += self.characters[index]
            else:
                decrypted_message += char  # Оставляем символы без изменений
        return decrypted_message

    def encrypt(self, message: str, key: int) -> str:
        """Шифрует сообщение с использованием заданного ключа."""
        encrypted_message = ''
        for char in message:
            if char in self.characters:
                index = (self.characters.index(char) + key) % self.char_length
                encrypted_message += self.characters[index]
            else:
                encrypted_message += char  # Оставляем символы без изменений
        return encrypted_message


def find_key(encrypted_message: str) -> None:
    """Находит ключ для расшифровки сообщения."""
    cipher = CaesarCipher()
    for key in range(cipher.char_length):
        decrypted_message = cipher.decrypt(encrypted_message, key)
        if "пароль" in decrypted_message.lower() or "password" in decrypted_message.lower():  # Проверяем на наличие слова 'пароль' или 'password'
            print(f'Подобранный ключ: {key}. Расшифрованное сообщение: {decrypted_message}')
            break
    else:
        print("Ключ не найден.")


if __name__ == "__main__":
    # Зашифрованное сообщение Антона
    encrypted_note = "o3zR v..D0?yRA0R8FR8v47w0ER4.R1WdC!sLF5D"

    # Поиск ключа
    find_key(encrypted_note)

    # Пример использования методов encrypt и decrypt
    cipher = CaesarCipher()
    original_message = "The vacation was a success"
    key = 3

    # Шифрование
    encrypted_message = cipher.encrypt(original_message, key)
    print(f'Зашифрованное сообщение: {encrypted_message}')

    # Расшифрование
    decrypted_message = cipher.decrypt(encrypted_message, key)
    print(f'Расшифрованное сообщение: {decrypted_message}')

    # Пример с ключом 0
    no_shift_message = cipher.encrypt(original_message, 0)
    print(f'Сообщение с ключом 0 (без изменений): {no_shift_message}')