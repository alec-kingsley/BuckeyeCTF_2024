# text-adventure documentation

This is the documentation for the text-adventure app, which the game developer forgot to write. I built this by reading through Ghidra. Java programs are easy to decompile since they preserve many symbol names.

When you first start the adventure, use the "enter" command to enter the main hall.

Each room will let you know if you can `go left`, `go middle`, or `go right`. `go back` can be used to go towards the starting room.


If there is an item in the room, you can use `take [item]`, for example: `take torch`.


If you reach a staircase, you can `go down` or `go up`.

Here's a map of the area you can explore, with items in parentheses
```
*********++++++++++//////////≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈ ( nnnnnnnnnn)
* DEAD  <> SEALED <>        <>  RIVER              (armor) )
* END   <> DOOR   <>         ≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈ (   (sword  )
* *******++++++++++         /                  (uuuuuuuuuuu)
                   /        /
                   /        /
                   /        /
                   / STAIRS /
                   /        /
                   / ^   ^  /
#########&&&&&&&&  __v   v _________
# KEY   <> SPIDER <>   ENTRY HALL  |===============$$$$$$$$$$$$$$$$
# ROOM  <>  HALL  <>      (torch)  <>  BRIDGE     <> CRYSTAL ROOM $
# (key) #&&&&&&&&& _____^  ^_______|===============$    (rope)    $
#########                                          $$$$$$$$$$$$$$$$
```

Below are some special commands that can be used in certain rooms:

## Bridge
`go across` - cross bridge

## River
`throw rope` - throws rope to go across river (requires rope)

## Spider Hall
`cut` - cuts through webs (requires sword)

## Sealed Door
`use key` - uses key

## Dead End
`reach through the crack in the rocks` - prompts the response "What? What crack in the rocks?", to which you can say `the crack in the rocks concealing the magical orb with the flag`, which gives the flag


