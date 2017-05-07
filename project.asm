;-------------------------------data
dane	segment
	Arg			db	200	dup	('$')	;tabila sparsowanych argumentów
	offsetArg	dw	10	dup	(?)		;tablica z offsetami argumentów 
	dlugoscArg	db	10	dup	(?)		;tablica przechowująca długości argumentów 
	liczbaArg	dw	0				;liczba argumentów
	lpZnakow	dw 	?				;ilość znaków na wejściu
	
	brakArg		db	'Nie podano argumentow $'
	info 		db  13,10, 'Podano tylko jeden argument $'
	info1		db	13,10, 'Podano za duzo argumentow! $'
	info2		db	13,10, 'Zly numer opcji $'
	info3		db	13,10, 'Nieprawidlowa dlugosc klucza $'
	info4		db	13,10, 'Klucz zawiera niedozwolone znaki $'
	info5		db	'Klucz jest poprawny $', 10, 13
	info6		db 	13,10, 'Mozliwe opcje to 1 i 2, podano zly numer opcji $'
	info7		db 	13,10, 'Wybrano opcje z modyfikacja $'
	
	binArg		db	16 dup	(?)		;tablica zawierająca binarną reprezentację klucza
	modBinArg	db	16 dup (?)		;tablica przechowująca klucz po modyfikacji 
	szachownica	db	153 dup (0)		;szachodnica 17X9 wypełniona zerami
	ostatniePole dw	1 				;miejsce w którym goniec skończył swoją drogę
	
	znaczki		db ' ','.','o','+','=','*','B','O','X','@','%','&','#','/','^'	
	goraRamki	db	13,10, '+--[ RSA 1024]----+', 10,13, '$'
	dolRamki	db	'+-----------------+ $'
	nowaLinia	db	13,10, '$'	
dane			ends
;-------------------------------data

	
kod		segment
assume cs:kod, ds:dane, ss:stos1
;-------------------------------main
start:
		mov		sp, offset wstosu
		mov		ss, ax
		mov		ax, seg wstosu  ;inicjowanie stosu
		
		mov		ax, seg dane
		mov		ds, ax
	
		call	uruchomParser
		call	sprawdzPoprawnosc
		call	postacBinarna
		call 	sprawdzCzyModyfikacja
		call	idzGoncem
		call 	stworzFingerptint
		call	drukujFingerprint
		
	zakonczProgram:
		mov		ah, 4ch
		int		21h
;-------------------------------main

;_____________________________________________________________________________________
;				~URUCHOM PERSER~ DANE:
;				DI ilość sprawdzonych już znaków
;				BL ilość bajtów zajmonanych przez linię komend		
;				BX służy jako zmienna pomocnicza, tu jest to liczba znaków z lini komend		
;				DL wskazuje na dany element z ciągu znaków z lini komend
;				DS wskazuje na segment zawierający tablicę argumentów
;				SI offset talbicy argumentów
;				CX offset talbicy offsetów
;				AL przyjmuje wartość znaku z lini komend
;_____________________________________________________________________________________
;-------------------------------runParser
uruchomParser 	PROC

		push	ax 
		push	bx
		push	cx 
		push	dx
		push	di
		push	si
		
		xor		si, si
		xor		di, di 						;na początki DI=0, tyle znaków z lini komend zostało przjrzane
		
		mov		bl, byte ptr es:[80h] 		;BL otrzymuje ilość bajtów zajmowanych przez linię komend
		cmp		bx, 1				 		;porównaj liczbę bajtów z 1
		jbe		niemaArg					;jeśli BL<=1 to nie podano argumentów
		
		mov		ax, seg	Arg 
		mov		ds, ax						;DS wskazuje na segment w którym znajduje się tablica argumentów
		mov		si,	offset Arg				;SI wskazuje na offset tablicy argumentów, będzie iterowany gdy znajdzie się nie biały znak
		mov		cx,	offset offsetArg 		;CX wskazuje na offset	tablicy offsetów, będzie iterowany gdy znajdzie się nowy argument
		
		dec		bx 							;w miejscu 81h jest spacja, która jest niezbędna gdy trzeba wywołać program z parametrami, będzie ona pomijana
		mov		word ptr ds:[lpZnakow], bx 	;liczba znaków pomniejszona o jeden 
		
		xor		ax,ax
		mov		al, byte ptr es:[82h]		;AL staje się pierwszym znakiem z lini komend
		call	czyBialy 					;sprawdzam czy AL to biały znak
		cmp		bx, 1 						;czy BX=1? czy AL to biały znak?
		jne		parsuj						;jeśli nie to rozpoczyna się proces zapisywania argumentu do tablicy Arg
	
	przewinBiale:
			call	przewin	
			cmp		di, ds:[lpZnakow]
			je		opuscParser
	parsuj:
			call	parsuje 
			cmp		di, ds:[lpZnakow]		;czy sprawdzono już wszystkie znaki?
			jne		przewinBiale
			jmp		opuscParser
			
	niemaArg:
			mov		dx, offset brakArg
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
	
	opuscParser:
			pop 	si
			pop		di
			pop		dx 
			pop		cx
			pop		bx
			pop		ax
		
ret
uruchomParser	ENDP 
;-------------------------------runParser	

;_____________________________________________________________________________________
;				~CZY BIAŁY~ DANE:
;				BX określa typ znaku, 1-biały, 0-inny znak
;				AL przyjmuje wartość znaku z lini komend
;_____________________________________________________________________________________
;-------------------------------ifWhite
czyBialy	PROC
		xor		bx, bx 		;zakładam, że to nie biały, BX=0
		cmp		al, 32 		;czy to spacja?
		je		bialy	
		cmp		al, 9		;czy to tab?
		je		bialy

		jmp		wyjscie 	;jesli żadne z powyższych to wyjdź	
	bialy:
			mov		bx, 1
	
	wyjscie:
ret
czyBialy	ENDP
;-------------------------------ifWhite


;_____________________________________________________________________________________
;				~PARSUJ~ DANE:
;				AX zmienna pomocnicza
;				CX offset talbicy offsetów 
;				DI wskazuje miejsce, w którym będzie zapisany dany offset argumentu w tablicy offsetArg
;				SI offset talbicy argumentów, będzie zwiększany po każdym dodaniu nowego znaku do tablicy Arg

;				W PĘTLI ZAPISZZNAK:
;				AL przyjmuje wartość znaku z lini komend
;				DL długość danego argumentu
;				DI ilość sprawdzonych znaków z lini komend
;_____________________________________________________________________________________
;-------------------------------parse
parsuje		PROC	
		push	bx
		push	dx 
		push	di 
		push	ax 
		
;		offset argumentu		
		mov		ax, cx 						;mam do czynienia z pierwszym znakiem argumentu, CX to offset tablicy offsetów
		mov 	di, ax 						;DI to offset tablicy offsetów
		mov		word ptr ds:[di], si 		;zapisuje w tą komórkę SI czyli offset argumentu- początkowo jest to offset tablicy Arg 
		inc		cx 
		inc 	cx 							;offsety argumentów to słowa, dlatego, aby przjeść do kolejnej komórki w tablicy offsetArg CX=CX+2
		inc		ds:[liczbaArg] 				;właśnie wpisany został początek jakiegoś argumentu więc trzeba zwiększyć ogólną liczbę argumentów
		xor		dl, dl				 		;zaczynam nowy argument, jego długość to narazie DL=0
		
		pop		ax
		pop		di
		
		
;		wpisz argument						
	zapiszZnak:
			mov		byte ptr ds:[si], al 	;wstaw znak AL w odpowiednie miejsze tablicy argumentów Arg 
			inc		dl						;zwieksz długość parametru
			inc		di						;zwieksz liczbe sprawdzonych znaków
			cmp		di, ds:[lpZnakow]		;czy DI jest równe liczbie wszystkich znaków? to by oznaczało koniec porównywania
			je		stop 					;jesli tak, wyjdź z pętli
			
			inc		si						;przejdź do kolejnej komórki w tablicy argumentów
			mov		al, byte ptr es:[82h+di] 
			xor		bx, bx
			call	czyBialy
			cmp 	bx, 1
			jne		zapiszZnak 				;jesli kolejny AL to nadal nie biały znak to dokładamy go do talbicy Arg

			
;		długość argumentu		
	stop:									;właśnie znaleziono biały znak to oznacza, że argument się skończył (lub już sprawdzono wszytskie znaki), trzeba obliczyć długość argumentu 
			push	di 						;odkładam DI, teraz przyda mi się do policzenia długości argumentu
			
			inc 	si 						;pomiędzy jednym a drugim argumentem trzeba zostawić puste miejsce, będzie tam dolar
			mov		di, offset dlugoscArg	;DI zawiera nr komórki w której znajduje się początek tablicy z długościami argumentów
			mov		ax, word ptr ds:[liczbaArg]	;AX to numer argumentu który teraz był wpisywany
			add		di, ax 					;offset tablicy z długościami + numer argumentu daje adres komórki w której będzie zapisana informacja o długości tego argumentu
			dec		di 						;DI pomniejszony o 1 wskazuje dokładnie na odpowidnią komórkę, czemu? bo adres+0 zawiera dłguość 1 arg, adrs+1 zawiera ardes 2 arg, itd
			mov		byte ptr ds:[di], dl 	;umieść długość parametru w odpowiednim miejscu
			
			pop		di
			pop		dx
			pop		bx 
ret
parsuje ENDP
;-------------------------------parse

;_____________________________________________________________________________________
;				~PRZEWIŃ BIAŁE ZNAKI~ DANE:
;				DI liczba sprawdzonych znaków
;				AL przyjmuje wartość znaku z lini komend
;				BX określa typ znaku, 1-biały, 0-inny znak
;_____________________________________________________________________________________
;-------------------------------scroll
przewin		PROC								;procedura przewija białe znaki - przesuwa DI dopuki nie napotka nie białego znaku
		push	bx
	przewijam:
			inc		di							;pod adresem 82h+di był biały znak, to patrzę czy kolejny to też biały
			cmp		di, ds:[lpZnakow] 			;czy sprawdzono już wszystkie znaki?
			je		koniecPrzewijania
			
			mov		al, byte ptr es:[82h+di]	;jak nie to AL dostaje kolejny znak
			xor		bx, bx
			call	czyBialy					;czy jest on biały?
			cmp		bx, 1 						;jeśli BX=1 to tak
			je		przewijam					;więc trzeba go przewinąć
			
	koniecPrzewijania:
			pop		bx
ret
przewin ENDP
;-------------------------------scroll

;_____________________________________________________________________________________
;				~SPRAWDŹ POPRAWNOŚĆ~ DANE:
;				AX zmienna pomocnicza
;				DI wskazuje na pojedynczy znak z argumentu
;				DX do wyświetlania komunikatów
;				CX licznik pętli
;				AL przechowuje kod danego znaku
;_____________________________________________________________________________________
;-------------------------------isCorrect
sprawdzPoprawnosc	PROC
		push	ax
		push	cx
		push	dx
		push	di

		
;		sprawdź liczbę argumentów
		mov		al, byte ptr ds:[liczbaArg]		;sprawdzam czy podano tylko jeden argument
		cmp		al, 2
		jb		komunikat						;jeśli AL mniejsze od 2 to za mało argumentów				
		ja		komunikat1						;jeśli AL jest większe od 2 to wypisz odpowiedni komunikat
		
;		sprawdź długość argumentów
		mov		di, offset dlugoscArg			;sprawdzam czy opcja ma odpowiednią długość
		mov		al, byte ptr ds:[di]
		cmp		al,	1
		jne		komunikat2						;jeśli dłógość jest różna od 1 wypisz odpowiedni komunikat 
		
		mov		al, byte ptr ds:[di+1]			;sprawdzam czy klucz ma odpowiednią długość
		cmp		al,	32
		jne		komunikat3						;jeśli dłógość jest różna od 32 wypisz odpowiedni komunikat 
		
		
;		sprawdz czy argument jest zapisany w kodzie szesnastkowym
		mov		si, offset offsetArg
		mov		di,	ds:[si+2]
		xor		cx, cx
		dec		di								;ponieważ na początku pętli jest on inkrementowany, nie chcę opuścić sprawdzania pierwszego znaku
		sprawdzZnak:
			inc		cx
			inc		di
			mov		al, byte ptr ds:[di]		;AL to znak do sprawdzenia
			
			cmp		al, '0'
			jb		zlyZnak						;jesli kod AL jest mniejszy od kodu zera to znak jest spoza zakresu
			cmp		al, '9'
			jbe		cyfra						;jesli kod AL jest mniejszy bądź równy kodowi dziewiątki to znak jest prawidłowy
			cmp		al, 'a'	
			jb		zlyZnak						;jesli kod AL jest mniejszy od kodu a to znak jest spoza zakresu
			cmp		al, 'f'
			ja		zlyZnak 					;jesli kod AL jest większy od f to znak nie jest prawidłowy
			
;			jeśli żadne z powyższych to znak jest literą
;			plan jest taki aby w talbicy Arg znajdowały się liczby od <0;16> a nie ich kody
			litera:

				mov		al, 87					;dlatego od kodu danej litery np c=99 odejmniemy 87 czyli kod a=97 pomniejszony o 10 (tak, aby powstały liczby z zakresu 10...19)
				sub		byte ptr ds:[di], al   	;w tablicy zostanie zapisane c jako 12- zgodnie z kodem szesnastkowym
				jmp		czyKoniec				;czy sprawdzono już wszystkie znaki?
				
			cyfra:
				mov		al, '0'					;od kodu danej liczby, np trójki=51 odejmniemy kod zera=48				
				sub		byte ptr ds:[di], al	;w tablicy zostanie zapisana ich róznica, z powyższego przykładu było by to 3
				jmp		czyKoniec				;czy sprawdzono już wszystkie znaki?
				
			czyKoniec:
				cmp		cx, 32					;czy sprawdzono już wszystkie 32 znaki?
				jb		sprawdzZnak 			;jesli cx jest mniejsze od 32 sprawdzaj dalej
				
			jmp koniecSprawdzania				;jeśli CX=32 to znaki sprawdzone, wyjdź z pętli
			
			zlyZnak:
				jmp 	komunikat4 				;jeśli znak jest spoza zakresu, wypisz odpowiedni komunikat
			
			
;		KOMUNIKATY O BŁĘDACH
		komunikat:
			mov		dx, offset info
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
		
		komunikat1:
			mov		dx, offset info1
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
			
		komunikat2:
			mov		dx, offset info2
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
			
		komunikat3:
			mov		dx, offset info3
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
			
		komunikat4:
			mov		dx, offset info4
			mov		ah, 9
			int		21h
			jmp		zakonczProgram
		
		koniecSprawdzania:
			mov		dx, offset info5
			mov		ah, 9
			int		21h
			
			pop 	di
			pop		dx
			pop   	cx
			pop		ax
ret
sprawdzPoprawnosc	ENDP
;-------------------------------isCorrect


;_____________________________________________________________________________________
;				~ZMIEŃ NA POSTAĆ BINARNĄ~	DANE:
;				DI wskazuje na liczbę z tablicy argumentów
;				SI wskazuje na komórkę tablicy z binarnymi argumentami, do której będzie zapisywany wynik poniżzych operacji
;				CX licznik, pętla musi być wykonana 16 razy
;				CL potrzebne do przesunięcia bitowego: do instrukcji shl
;				AL młodsza liczba w tablicy Arg
;				BL starsza liczba w tablicy Arg
;_____________________________________________________________________________________
;-------------------------------toBinary
postacBinarna	PROC

	push	bx
	push	cx
	push	dx
	push 	di
	push	si

	mov		si, offset offsetArg
	mov		di, ds:[si+2] 				;załaduj DI offsetem klucza
	mov		si, offset binArg 			;załaduj SI offsetem tablicy z binarną postacią klucza
	mov		cx, 16						;licznik bajtów do zapisania
	
	zamien:	
		push	cx 
		mov		al, byte ptr ds:[di]	;AL otrzymuje starszą liczbę 
		inc		di						;przejscie do kolejnej komórki
		mov		cl, 4					;wartość przesunięcia
		shl		al, cl 					;przesuń logicznie w rejestrze AL w lewo o 4 bity, 4 najmłodsze będą zerami
		
		mov		bl, al					;BL staje się starszą liczbą
		mov		al, byte ptr ds:[di]	;AL to młodsza liczba
		inc		di						;przejdź do kolejnej liczby z tablicy Arg
		add		al, bl					;AL dostaje wynik operacji ADD na AL i BL
		mov		byte ptr ds:[si], al	;zapisz w tablicy binArg wynik tej operacji
	
		inc		si						;przejdż do kolejnej pustej komórki w tablicy binArg
		pop 	cx 
	loop	zamien
	
	pop		si
	pop		di
	pop		dx
	pop		cx
	pop		bx
	
	
ret
postacBinarna	ENDP 
;-------------------------------toBinary

;_____________________________________________________________________________________
;				~SPRAWDŹ CZY MODYFIKACJA~	DANE:
;				DI wskaźnik na offset argumnetów
;				AL równy 1 lub 2- numer opcji czyli pierwszy argumnet
;_____________________________________________________________________________________
;-------------------------------isWithModyfication
sprawdzCzyModyfikacja PROC
	push	ax
	push	dx
	push	di
	push 	si
	
	mov		di, offset Arg
	mov		al, byte ptr ds:[di]
	cmp		al, '1'					;czy pierwszy argument jest równy 1? 
	je		koniecSprMod			;jeśli tak to wybrano opcje bez modyfikacji
	cmp		al, '2'					;czy pierwszy argument to 2?
	je		modyfikuj				;jeśli tak to wybrano opcje z podyfikacją
	
	mov		dx, offset info6		;jeśli żadne z powyższcych to wypisz komunikat
	mov		ah, 9					
	int		21h
	jmp		zakonczProgram			;i zakończ program

		
	modyfikuj:
		mov		dx, offset info7	
		mov		ah, 9					
		int		21h
		call 	zmodyfikujDane
		
		koniecSprMod:
		pop		si
		pop		di
		pop		dx
		pop		ax
		
ret
sprawdzCzyModyfikacja	ENDP
;-------------------------------isWithModyfication

;_____________________________________________________________________________________
;				~SZMODYFIKUJ DANE~	DANE:
;				CX licznik
;				AL, BL xorowane bajty
;				DI wskazuje na bajt w tablicy argumentów w postaci binarnej
;				SI wskazuje na miejsce w tablicy z wynikami modyfikacji xor		
;_____________________________________________________________________________________
;-------------------------------modifyData
zmodyfikujDane	PROC
	push	si 
	push 	di
	push	ax
	push	bx
	push	cx
	
	mov		cx, 15 					;pierwszy bajt będzie xorowany indywidualnie, poza pętlą
	mov		di,	offset binArg
	mov		si, offset modBinArg
	inc		si 						;zapisuje w tej tablicy od drugiego elemetu, pierwszy dołączę na końcu
	xoruj:
			mov 	al, byte ptr ds:[di]
			mov 	bl, byte ptr ds:[di+1]
			xor		bl, al 			;wynik xorowania idzie do drugiego w parze al,bl bajtu
			mov		byte ptr ds:[si], bl
			inc		si
			inc		di
			loop 	xoruj
	
	mov		si, offset modBinArg
	mov 	al, byte ptr ds:[di] 	;al to ostani bajt
	mov		di, offset binArg
	mov 	bl, byte ptr ds:[di] 	;bl to pierwszy bajt
	xor		bl, al
	mov		byte ptr ds:[si], bl 	;wstaw na piersze miejsze tablicy modBinArg wynik xorowania ostatneigo bajtu z pierwszym
	
	mov		cx,16
	mov		di,	offset binArg
	mov		si, offset modBinArg
	przepisz:						;wynik operacji xor przepisz do głównej tablicy z kluczem
			mov 	al, byte ptr ds:[si]
			mov		byte ptr ds:[di], al
			inc 	si
			inc		di
	loop 	przepisz
	
	pop		cx 
	pop 	bx 
	pop		ax
	pop		di
	pop		si
ret
zmodyfikujDane	ENDP 
;-------------------------------modifyData
;_____________________________________________________________________________________
;				~IDŹ GOŃCEM~ DANE:
;				DI wskazuje na dany bajt z tablicy binArg
;				SI określe obecne położenie gońca
;				CX to licznik, ma być sprawdzone 16 czyli wykonae 64 ruchów
;				BL dostaje wartość danego bajtu z binArg
;_____________________________________________________________________________________
;-------------------------------chessMan
idzGoncem	PROC

	push	bx
	push	cx
	push	dx
	push 	di
	push	si
	
	mov		di, offset binArg				;DI równy pierwszemu bajtowi w binArg
	mov		si, 76							;położenie startowe pionka
	mov		cx, 16							;licznik
	
	analizuj:
		push	cx
		mov		bl, byte ptr ds:[di]		;BL równe bajtowi z binArg
		inc		di 							;przejdż do kolejnego bajtu
		
		mov		cx, 4 						;w bajcie są 4 pary bitów, tyle kroków trzeba będzie zrobić
		analizujPareBitow:
			call	zrobRuch
		loop	analizujPareBitow
		
		pop		cx
	loop	analizuj
	
	mov		word ptr ds:[ostatniePole], si	;zapisz numer komórki w której goniec wylądował na końcu	
	pop 	si
	pop		di
	pop		dx
	pop		cx
	pop 	bx

ret
idzGoncem 	ENDP
;-------------------------------chessMan

;-------------------------------makeMove
zrobRuch	PROC
	
	shr		bl, 1 			;przesun bity o 1 w prawo, ostatni wypadnie, znajdzie się w rejestrze flag cf
	jc		krokwPrawo		;jesli cf=1 to oznacza, że dana para to 01 lub 11, w obu przypadkach trzeba wykonać krok w prawo
	jnc		krokwLewo		;jesli cf=0 to możliwe pary to 10 i 00, krok w lewo
	
	krokwPrawo:
		call	idzwPrawo
		shr		bl, 1 		;znowu przesuwam w prawo o 1, jaki jest starszy bit w tej parze?
		jc		krokwDol 	;to 11 goniec idzie w prawo potem w dół
		jnc		krokwGore   ;to 01 goniec idzie w prawo potem w górę
		
	krokwLewo:
		call	idzwLewo
		shr		bl, 1 		;zprzesuwam w prawo o 1, jaki jest starszy bit w tej parze?
		jc		krokwDol	;to 10 goniec idzie w lewo potem w dół
		jnc		krokwGore   ;to 00 goniec idzie w lewo potem w górę
		
	krokwDol:
		call	idzwDol
		call	zapiszRuch
		jmp		kolejnaPara
		
	krokwGore:
		call	idzwGore
		call	zapiszRuch 
		jmp		kolejnaPara
		
	kolejnaPara:	
ret
zrobRuch	ENDP
;-------------------------------makeMove

;-------------------------------turnRight
idzwPrawo	PROC
	push	dx
	
	mov		ax, si		;AX wymagane przy instrukcji div
	mov		dl, 17		;17 to nasz dzielnik
	div		dl			;AX=AX/DL jeśli pole na którym stoi pionek to 16, 51, itd to oznacza, że jest to prawa krawędź, nie da się pójść dalej w prawo
	cmp		ah, 16		;w AH została zapisana reszta z powyższego dzielenia
	je		koniecP 	;jesli reszta=16 to znaczy że pionek stoi na prawej krawędzi
	inc		si			;jeśli stoi gdzieś indziej to może przesunąć się w prawo, wartość jego pola wzrasta o 1
	koniecP:
		pop		dx
ret
idzwPrawo	ENDP
;-------------------------------turnRight

;-------------------------------turnLeft
idzwLewo	PROC
	push	dx
	
	mov		ax, si		;AX wymagane przy instrukcji div
	mov		dl, 17		;17 to nasz dzielnik
	div		dl			;AX=AX/DL jeśli pole na którym stoi pionek to 0, 17, itd to oznacza, że jest to lewa krawędź, nie da się pójść dalej w lewo
	cmp		ah, 0		;w AH została zapisana reszta z powyższego dzielenia
	je		koniecL 	;jesli reszta=0 to znaczy że pionek stoi na lewej krawędzi
	dec		si			;jeśli stoi gdzieś indziej to może przesunąć się w lewo, wartość jego pola maleje o 1
	koniecL:
		pop		dx
ret
idzwLewo	ENDP
;-------------------------------turnLeft

;-------------------------------goDown
idzwDol		PROC
	cmp		si, 136 	;136 to numer od którego zaczynają się pola z dolnej krawędzi
	jae		koniecD		;jesli SI jest większe bądź równe 136 to pionek nie może pójść dalej w dół
	add		si, 17		;jeśli SI ma inną wartość to przechodzi do wiersza niżej, wartość SI wzrasta o 17
	koniecD:
ret
idzwDol		ENDP
;-------------------------------goDown

;-------------------------------goUp
idzwGore	PROC
	cmp		si, 16 		;16 to numer do którego pola leżą na górnej krawędzi
	jbe		koniecG		;jesli SI jest mniejsze bądź równe q6 to pionek nie może pójść dalej w górę
	sub		si, 17		;jeśli SI ma inną wartość to przechodzi do wiersza wyżej, wartość SI maleje o 17
	koniecG:
ret
idzwGore	ENDP
;-------------------------------goUp

;-------------------------------saveMove
zapiszRuch	PROC
	push	di
	push	ax

	mov		di, offset szachownica 	;DI wskazuje na początek szachownicy
	add		di, si 					;teraz DI wskazuje na pole na którym stoi pionek na szachownicy
	mov		al, 1
	add		ds:[di], al				;zwiększ liczbę odwiedzeń tego pola o 1
	
	pop     ax
	pop		di
ret
zapiszRuch	ENDP
;-------------------------------saveMove

;_____________________________________________________________________________________
;				~STWÓRZ FINGERPRINT~ DANE:
;				DI wskazuje na kolejne pola w szachodnicy
;				SI wskazuje na znak, który chcemy wstawić w dane pole zamiast liczby odwiedzin tego pola
;				CX licznik, pilnuje by wszystkie 153 pola zostały zmodyfikowane
;				BL liczba odwiedzin danego pola
;_____________________________________________________________________________________
;-------------------------------createFingerprint
stworzFingerptint	PROC
	push	di
	push	si
	push	cx
	push	bx
	push	dx
	
	mov		di, offset szachownica
	mov		si,	offset znaczki
	mov		cx, 153
	
	zamienNaZnak:
	push	si 
	xor		bx, bx 
	mov		bl, byte ptr ds:[di] 			;BL to liczba odwiedzin danego pola
	cmp		bl, 14
	jbe		liczbaNaZnak					;jeśli liczba odwiedzin jest mniejsza bądź równa 14, zamień na znak
	mov		bl, 14							;jeśli odwiedzin było więcej, traktuj to jako 14 odwiedzin
	
	liczbaNaZnak:
			add		si, bx 					;pezsuń wskaźnik znaczków o BX miejsc (BX to liczba odwiedzin)
			mov		al, byte ptr ds:[si] 	;AL dosteje potrzebny znak 
			mov		byte ptr ds:[di], al 	;wsadź ten znak na miejsce liczby odwiedzin danego pola
			inc		di 						;przejdź do kolejnego pola
	
	pop 	si
	loop	zamienNaZnak
	
											;znaki wstawione, trzeba jeszcze zaznaczyć pierwszy i ostatni krok
	mov		di, offset szachownica
	mov		byte ptr ds:[di+76], 'S'		;w miejscu startu gońca umieść S
	
	mov 	si, word ptr ds:[ostatniePole] 	;SI dostaje numer pola w którym goniec zakończył swoją drogę
	add		di, si							;niech DI wskazuje na tą komórkę
	mov		byte ptr ds:[di], 'E' 			;teraz niech zostanie tam wstawiona literka E 
	
	pop		dx
	pop		bx
	pop		cx
	pop		si
	pop		di
	
ret
stworzFingerptint	ENDP
;-------------------------------createFingerprint

;_____________________________________________________________________________________
;				~DRUKUJ FINGERPRINT~ DANE:
;				DI to znak do wydrukowania
;				CX licznik
;_____________________________________________________________________________________
;-------------------------------displayFingerprint
drukujFingerprint	PROC
	push	dx
	push	cx
	push	bx
	push	di
	push	si
	
	mov		di, offset szachownica 		;DI to pierwszy znak do wydrukowania
	
	mov		dx, offset goraRamki
	mov		ah, 9
	int 	21h
	
	mov		cx, 9 						;tyle będzie wierszy
	drukuj:
		push	cx
		mov 	dl,'|' 					;na początku każdego wiersza drukuj ramkę
		mov 	ah,6 
		int 	21h
		
		mov		cx, 17 					;tyle znaków w wierszu trzeba wydrukować
		drukujZnak:
			mov		dl, byte ptr ds:[di] ;wyświetl znak
			mov		ah, 6
			int 	21h
			inc		di					;przejdź do kolejnego znaku
		loop drukujZnak
		
		mov 	dl,'|' 					;na końcu każdego wiersza drukuje ramke
		mov 	ah,6 
		int 	21h
		
		mov		dx, offset nowaLinia 	;przjedź do nowej lini
		mov		ah, 9
		int 	21h
		
		pop 	cx
	loop	drukuj
	
	mov		dx, offset dolRamki
	mov		ah, 9
	int 	21h
	
	pop		si
	pop		di
	pop		bx
	pop		cx
	pop		dx

ret
drukujFingerprint	ENDP
;-------------------------------displayFingerprint
kod 	ends


;-------------------------------stack
stos1 segment stack
	dw 200 dup(?)
wstosu	dw ? 
stos1 ends
;-------------------------------stack
end		start
