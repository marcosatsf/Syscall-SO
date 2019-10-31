
# Introdução
Este projeto deverá permitir ao aluno familiarizar-se com os detalhes de implementação de chamadas de sistema (_system calls_) em um _kernel Linux_. Espera-se que ao final do projeto, cada aluno seja capaz de implementar, compilar, instalar e testar um _kernel Linux_ modificado contendo duas novas chamadas de sistema que permitam a programas de usuário armazenar e ler arquivos de forma cifrada em um sistema _Linux_ através do uso da _API_ criptográfica do _kernel_.

# Descrição do projeto
O projeto consiste em implementar em um kernel Linux duas novas chamadas de sistema: `write_crypt` e `read_crypt`.

## Write_crypt
A chamada de sistema `write_crypt` deve permitir que programas em espaço de usuário possam armazenar arquivos de forma cifrada, utilizando o algoritmo AES em modo ECB para cifrar os dados.
A chave simétrica usada para cifrar os dados deverá ser definida no código-fonte da chamada de sistema `write_crypt`, só podendo ser modificada através de uma recompilação do _kernel_.
O formato da chamada de sistema `write_crypt` é mostrado a seguir:
```C++
ssize_t write_crypt(int fd, const void *buf, size_t nbytes);
```
onde:
| Argumento | Descrição |
|--------------|----------|
|`fd` | Descritor de arquivos obtido através da chamada de sistema `open`. É um valor inteiro. |
|`buf` | Ponteiro para um vetor de caracteres, cujo conteúdo deve ser escrito no arquivo referenciado pelo descritor de arquivos `fd `.|
|`nbytes` | Número de _bytes_ do vetor de caracteres apontado por `buf` que devem ser escritos no arquivo referenciado pelo descritor de arquivos `fd`.|

O valor de retorno e os códigos de erro retornados pela chamada `write_crypt` devem seguir o mesmo modelo da chamada de sistema `write`, já existente em sistemas _Linux_.
A chamada de sistema `read_crypt` deve permitir que programas em espaço de usuário possam ler arquivos cifrados com a chamada `write_crypt`, utilizando o algoritmo AES em modo ECB para decifrar os dados lidos.
A chave simétrica usada para decifrar os dados deverá ser definida no código-fonte da chamada de sistema `read_crypt`, só podendo ser modificada através de uma recompilação do _kernel_.

## Read_crypt
O formato da chamada de sistema `read_crypt` é mostrado a seguir:
```C++
ssize_t read_crypt(int fd, void *buf, size_t nbytes);
```
onde:
| Argumento | Descrição |
|--------------|----------|
|`fd` | Descritor de arquivos obtido através da chamada de sistema `open`. É um valor inteiro. |
|`buf` | Ponteiro para um vetor de caracteres, no qual devem ser armazenados os _bytes_ lidos do arquivo referenciado pelo descritor de arquivos `fd`|
|`nbytes` | Número de _bytes_ que devem ser lidos do arquivo referenciado pelo descritor de arquivos `fd` e armazenados no vetor de caracteres apontado por `buf`.|

O valor de retorno e os códigos de erro retornados pela chamada `read_crypt` devem seguir o mesmo modelo da chamada de sistema `read`, já existente em sistemas _Linux_.
Repare que o processo de cifragem dos arquivos será transparente para os programas em espaço de usuário. Isso significa que ao gravar um arquivo no sistema de arquivos utilizando a chamada de sistema `write_crypt`, o conteúdo do arquivo será armazenado cifrado, mas ao ler o arquivo utilizando a chamada de sistema `read_crypt`, o conteúdo retornado será o conteúdo já decifrado.

## Testes
Para testar o correto funcionamento das chamadas de sistema implementadas, devem ser implementados programas em espaço de usuário que permitam abrir um arquivo e realizar operações de escrita e leitura utilizando as chamadas de sistema `write_crypt` e `read_crypt`, além
de programas em espaço de usuário que permitam abrir um arquivo e realizar operações de escrita e leitura utilizando as chamadas de sistema `write` e `read`, de forma que seja possível demonstrar as corretas cifragem e decifragem dos dados.