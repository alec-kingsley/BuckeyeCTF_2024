# flagwatch

This challenge provides a  `flagwatch.exe` file with the description:
> Did you know that you can compile AutoHotKey scripts?

I did not, nor have I used AutoHotKey before.

The first thing I did was search how to decompile an AutoHotKey script, leading to [this](https://www.reddit.com/r/AutoHotkey/comments/kztfmp/decompile_ahk_file_from_exe/) Reddit post. One of the comments said
>  just open it in a text editor and the code is at the bottom

Weirdly enough, there it was:

```ahk
global flaginput := ""
logInput(key){
global flaginput
flaginput := flaginput . key
flaginput := SubStr(flaginput,-28)
checkInput()
}
checkInput(){
global flaginput
if (StrLen(flaginput) != 29)
return
if (SubStr(flaginput, 1, 5) != "bctf{" or SubStr(flaginput,0) != "}")
return
encrypted_flag := [62,63,40,58,39,40,111,63,52,50,53,63,104,48,48,37,3,61,3,55,57,37,48,108,59,59,111,46,33]
Loop 29
{
if ((encrypted_flag[A_Index] ^ 92) != Asc(SubStr(flaginput,A_Index,1))) {
MsgBox, You typed the wrong flag.
return
}
}
MsgBox, You typed the right flag!
}
~a::logInput("a")
~b::logInput("b")
~c::logInput("c")
~d::logInput("d")
~e::logInput("e")
~f::logInput("f")
~g::logInput("g")
~h::logInput("h")
~i::logInput("i")
~j::logInput("j")
~k::logInput("k")
~l::logInput("l")
~m::logInput("m")
~n::logInput("n")
~o::logInput("o")
~p::logInput("p")
~q::logInput("q")
~r::logInput("r")
~s::logInput("s")
~t::logInput("t")
~u::logInput("u")
~v::logInput("v")
~w::logInput("w")
~x::logInput("x")
~y::logInput("y")
~z::logInput("z")
~0::logInput("0")
~1::logInput("1")
~2::logInput("2")
~3::logInput("3")
~4::logInput("4")
~5::logInput("5")
~6::logInput("6")
~7::logInput("7")
~8::logInput("8")
~9::logInput("9")
~_::logInput("_")
~{::logInput("{")
~}::logInput("}")
```

This can be solved then with a pretty easy Python one-liner
```python
print(''.join(chr(x ^ 92) for x in [62,63,40,58,39,40,111,63,52,50,53,63,104,48,48,37,3,61,3,55,57,37,48,108,59,59,111,46,33]))
```

yielding the flag `bctf{t3chnic4lly_a_keyl0gg3r}`
