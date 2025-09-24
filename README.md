<p align = 'center'>
  <img src = 'assets/logo.svg' alt = "DevelR0X">
</p>

## Autores:

* Daniel Espinoza (D-Cryp7), _DevelR0X_.
* Borja Gomez (kub0x), _DevelR0X_.

## Contenido

Cada desafío contiene las siguientes carpetas y archivos:
* `archivos`: Carpeta que contiene las siguientes subcarpetas:
    * `adjuntos`: Son los archivos que se deben adjuntar en la plataforma principal del CTF. Serán vistos por los participantes.
    * `fuentes`: Archivos necesarios para montar el docker del reto. **El contenido de esta carpeta sólo debe ser visible para los revisores**.
    * `solucion`: Solución del desafío. **El contenido de esta carpeta sólo debe ser visible para los revisores**.
* `README.md`: Descripcion del reto y contexto.

_Nota: El archivo `archivos/fuentes/build-docker.sh` sólo debe tomarse como referencia, puede ser modificado para adaptarse a las necesidades de la plataforma._

## Desafíos

| Categoría | Nombre                           | Objetivo | Dificultad [⭐⭐⭐] |
| ---       | ---                              | ---      |   ---            |
| Misc    | [QGuess](Misc/QGuess) | Construir un circuito de entrelazamiento cuántico para predecir los resultados de un juego de adivinanza.| ⭐⭐⭐ |
| Crypto    | [Valoris](Crypto/Valoris) | Intercambiar bloques encriptados con AES-ECB para drenar el dinero de las cuentas de `admin` y `crypto` | ⭐⭐ |
| Crypto    | [Oni Link](Crypto/Oni%20Link) | Recuperar la llave criptográfica de ChaCha20 mediante un _Known Plaintext Attack_ y así encriptar un mensaje específico. | ⭐ |
