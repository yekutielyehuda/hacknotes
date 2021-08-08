# Cracking Binaries

## Pre-requisites

### Registers

### Flags

### Virtual Address \(VA\)

![](../.gitbook/assets/1%20%282%29.png)

Virtual Address = Es una dirección de un programa cuando esta cargado en la memoria.

### Image Base

![](../.gitbook/assets/imagebase1.png)

Image Base = Es la dirección del ejecutable en el Memory Map.

![](../.gitbook/assets/imagebase2.png)

Mapiado del ejecutable.

### Relative Virtual Address \(RVA\)

RVA = VA - IMAGE BASE

![](../.gitbook/assets/rva1.png)

Para calcular el RVA tenemos que restar la dirección de memoria con la dirección de Image Base

![](../.gitbook/assets/rva2.png)

Esta es la dirección de Image Base

![](../.gitbook/assets/rva3.png)

Calculamos las direcciones.

![](../.gitbook/assets/rva4.png)

El resultado es 1372:

![](../.gitbook/assets/rva5.png)

### Offset \(File Offset\)

File Offset = The location in RAM in which the file is located.

![Gather Offset with Highlighting the Line](../.gitbook/assets/offset1.png)

El número \#722 es el File Offset.

![Offset in Hex Editor](../.gitbook/assets/offset2.png)

Con un editor de Hexadecimal, vamos al offset 772.

![OPCODE in Hex Editor](../.gitbook/assets/offset3.png)

Aquí podemos ver el OPCODE.

### Calculación del Offset

Para calcular el offset necesitamos `RVA - PE Header Size + .text PointerToRawData`

![PE Header Size](../.gitbook/assets/calcoffset1.png)

El Size es 1,000

![PointerToRawData](../.gitbook/assets/calcoffset2.png)

El offset donde está el código es 400.

![Offset 400](../.gitbook/assets/calcoffset3.png)

![PE Header and Code](../.gitbook/assets/calcoffset4.png)

RVA - Image Base Size + .text PointerToRawData

![RVA Calculation](../.gitbook/assets/calcoffset5.png)

Podemos ver que el resultado del offset es 772.

![Offset Result 772](../.gitbook/assets/calcoffset6%20%281%29.png)

![Offset and OPCODE in Debugger](../.gitbook/assets/calcoffset7.png)

![Offset in Hex Editor](../.gitbook/assets/calcoffset8.png)

![OPCODE in Hex Editor \(Same\)](../.gitbook/assets/calcoffset9.png)

### Desplazamientos

![a4031731bfd53856c12f42c6c3d00ccf.png](:/0b8ff155d99345e3b916349dd2d9b325)

call = call directo, llama directamente a una dirección de memoria.

![73f838a182dc52cc6e21cdda186bbba7.png](:/48dbd889ed37478e86a8f40ca6da608a)

Si nos posicionamos en la instrucción y le damos a tecla Enter nos lleva a dirección que esta llamando.

![1a1032e474f0b1d92273967d4dee3d0e.png](:/891be29201514e78bdbbbe3ae3a5c8c6)

jmp = salto incondicional, simplemente hace jump \(siempre\)

### Label / Etiqueta

![fc89cfd266cf6e5a2f663ed2bed53902.png](:/0524a5588ea6481897981fa3800dd1aa)

Si le quito la etiqueta me va aparecer la dirección en donde va a saltar.

![8ca800335d7c0835c64d85005ed226ff.png](:/f6bf44a45b2447ef95b18b9215d2013d)

La dirección es 1F1755

![be7e8ed912bfdcdfa78fac3edfa4cd76.png](:/a860387f421742e9a14ea962c58a4c7b)

`E8` es el OPCODE de la instrucción `call`. Los bytes a continuación son `C4030000` son el desplazamiento.

### Calcular la dirección del CALL

![2da671774b442b9ccc279cb16f2865e9.png](:/eac22163edee4ec3b4599f4ad91978f4)

`Virtual Address + Desplazamiento en Little Endian + Cantidad de Bytes de la Instrucción`.

![737e4279f541b60c9d454e04b45099df.png](:/a800999671944f83b7e856568e0742f2)

Como resultado tenemos 001F173B representada en hexadecimal como 0x001F173B

![fa314303abcf6e2e86cac2c02131cf45.png](:/9faba7384f2048a892be639bd0ee061d)

### Calcular la dirección del JMP

![a64b25a8c637944e3c9a48a4b16d1867.png](:/75d4ef25c8154b6faf7f66e8a1a9e2a7)

Podemos ver que tenemos una flecha que apunta para arriba.

![a5977729472840790651f96249d77d72.png](:/e7f6f91a005746a68ccb903efbc028d8)

`Virtual Address + Desplazamiento en Little Endian + Cantidad de Bytes de la Instrucción`.

![b1edbd6108d9636793931676ab5d862b.png](:/85215f43b30d4849a82b1c5ed7c0e2bc)

El resultado es 001F11F0

![517d987bc4ce913f0ba4d8ccb05a26c6.png](:/d35604c4b102484fa1be9851609c178a)

Si nos paramos en la instrucción nos aparece esta ventanilla que nos indica a la dirección que va a brincar.

![ca29a90fad26990229ce062766e1a849.png](:/ca6331b80e374f8d888b327c7b661f86)

Si le damos enter pues brincamos a la dirección.

![2c8934c728a17e6fdc5c1c342e525295.png](:/d01c3fdb7b064c969cb0044ac0ec71a9)

También si le damos a la tecla 'Space' podemos ver la dirección.

### Calcular la dirección de un salto Condicional Negativo

![7cfdd8a6b34cfffd8766cb83b91e6c4d.png](:/15071f09a9dc4520954cd4513351e618)

EA = es negativo

Cuando consideramos el Signo/Signed debemos dividir el tamaño / 2.

`Virtual Address + Desplazamiento en Little Endian + Cantidad de Bytes de la Instrucción`.

Como EA es negativo debemos escirbir F adelante.

![7bb8f91ad6786606fc2bf73883f15859.png](:/147986a6112545ccb25bd382dfb7b66b)

Calculamos

![8b3603279438f6fdf9372f8dfe696975.png](:/4bd2e8c051714ddebbd718e9764783db)

Resultado

### Call Indirectos FF15 y \[dirección\]

![0fe324c49a89fad9726ddf780dd40995.png](:/4f2ff839d39541fe887dafa25146e67b)

FF15 = call indirectos

### Diferencias de Call Indirecto

![53b3dc7231445fd1b6605c8082a40f18.png](:/169263c93b424da0a9ad176c3e329ce3)

A diferencia del call directo, el indirecto contiene la dirección de donde va a llamar el programa y **NO** es un desplazamiento.

![062220b693251b6599532eb92a30ae6e.png](:/4250eedb4e9b4344989a49a3c130ca81)

![8ccc1a07158b7d344fc82ef7bd1caa55.png](:/26633218920d486eb6f6d0ad4f1b1034)

Vemos la dirección en Little Endian.

![198683670ae30f4aa8459c25c98f44fc.png](:/03ba8cface1d4133beb1188bb5a50d93)

Si cambiamos el valor de esta dirección.

![f0c7d4bab9dbee7fba061bcf8a510164.png](:/7411786b88f141ecae932805290c7b95)

Editamos los valores de esta dirección.

![1d48b818fb4864890eafd40a7c398dc7.png](:/66ba4cee44984068a3f600857627d707)

Cambiamos los valores por la dirección 001F13B8 y lo escribimos en Little Endian.

![c174329f0d824385fd4aa07d65fe86e6.png](:/4d937aebac784411a63be3ac9b304c14)

Después de cambiar los valores lo podemos ver ahora en rojo.

![0751a9fb7e5a54bd313d8b3069e4a940.png](:/be3d06e830934bd8b5c95ef61f341aea)

El nombre de la función ahora desaparece

![a190062b86b6957ba638953b490659a8.png](:/1749065ca650494a994f593de6b66384)

No vemos el comentario.

![1d810597958d357a25c1d0cd2c47fd50.png](:/ee5926ffbb3d4eb5838619c3cc26548f)

Ahora vamos a terminar llamando a esta dirección.

![592d7a6f4a35e953205b406c16a8d753.png](:/0f6ec31329fe48fb80a83dec112637b4)

Si presionamos Enter nos lleva a la dirección que llamo.

![9fee2f6e46183d2a19b7d1f02594753b.png](:/18fce9f6e95f49f2b4fc7a8d5b470565)

Lo que hay DENTRO de esta dirección puede cambiar pero la dirección es constante \(NO CAMBIA\).

### JMP Indirectos FF25 y \[dirección\]

![2b4133eddf9e130b7a420bfcaa24970c.png](:/080b6e06f5e64d11bcb461707c40dd41)

FF25 = jmp indirectos

Con Ctrl+B abrimos Find Pattern...

![acf922d9330da1b2964c8af947242a7a.png](:/2d4198a713254b819084c3492bdf7c00)

Hacemos clic en alguno.

![f6c24dd04a0fd73e574b4783296d046c.png](:/1e0edfc98234464092e8e1b3b8910161)

Podemos ver el OPCODE FF25.

La dirección también esta entre corechetes `[]`.

![d1ce605fa7bdf9967c8af7c7122a4bae.png](:/d1b899e4c9aa41d6861d5e78f57c8ad9)

![fc1a7a8cc4b0a52dd9e25f34e741a6bf.png](:/7965f1c14df8424b913aeff4b651e2cd)

![eb3d11a8ced483a2b94a73ce30a8676c.png](:/cbdcc62778be41ab940dec07a36da300)

![b1999379261a8c460e0589855d6cf28e.png](:/35fddd2f4d7042b8b0a1d5f8386ab920)

![230c6dcfbfea1986f60a5b98014e395c.png](:/97c79d752df74823a3aa77526dbf8bb4)

Si se cambia este valor hexadecimal pues va terminar saltando a el valor que este en esta dirección.

## Cracking Basics

### Changing the Logic

### Changing Hex Code

### Preventing the Logic from Uncracking

### Patching



