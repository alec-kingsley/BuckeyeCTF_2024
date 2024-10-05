# text-adventure documentation

This is the documentation for the text-adventure app, which the game developer forgot to write. I built this by reading through Ghidra. Java programs are easy to decompile since they preserve many symbol names.

When you first start the adventure, use the "enter" command to enter the main hall.

Each room will let you know if you can `go left`, `go middle`, or `go right`. `go back` can be used to go towards the starting room.


If there is an item in the room, you can use `take [item]`, for example: `take torch`.


If you reach a staircase, you can `go down` or `go up`.

Here's a map of the area you can explore, with items in parentheses

## Map

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
`unlock` - uses key to unlock the door

## Dead End
`reach through the crack in the rocks` - prompts the response "What? What crack in the rocks?", to which you can say `the crack in the rocks concealing the magical orb with the flag`, which gives the flag

## Example playthrough

```
You've been transported to a faraway magical land! Can you find the flag?
---
You find yourself standing at the opening of a vast, mysterious cave. The entrance looms before you, awaiting.

> enter

You feel the air grow cool as you pass through the threshold into the depths...
You find yourself in a central hall. It is faintly lit by a torch on the leftmost wall.
Through the gloom you barely make out three arches to ongoing passages: one left, one middle, and one right.

> take torch

You picked up the torch.

> go right

You pass through the right corridor...
You find yourself standing at the edge of an unfathomable chasm! Far off, you can hear fast running water below.
There lies a stone bridge spanning the gap, but it's little more than a few feet wide. It arches away from you, and disappears into the darkness.
The main hall lies behind you.

> go across

You slowly edge out on to the bridge... holding your breath...
...and eventually make it to the other side. Uh, good job.
On the other side of the bridge, you come upon a cavern covered in glistening pink crystals!
Some are so large you can see your reflection in them as they glisten from your torchlight.
Some of the crystals look mined away, but you don't see any sort of pickaxe. All that remains of the mining operation is a bundle of rope.

> take rope

You picked up the rope.

> go back

You brave the bridge once again...
...and again, safely make it across. Surefooted as they come.
You find yourself standing at the edge of an unfathomable chasm! Far off, you can hear fast running water below.
There lies a stone bridge spanning the gap, but it's little more than a few feet wide. It arches away from you, and disappears into the darkness.
The main hall lies behind you.

> go back

You return to the hall you entered through.
You find yourself in a central hall.
Through the gloom you barely make out three arches to ongoing passages: one left, one middle, and one right.

> go middle

You pass through the middle corridor...
You find yourself at the top of a long stair descending downward. You cannot make out the bottom.
Behind you lies the great hall you first entered through.

> go down

You muster all of your courage and wander down into the depths...
You are at the base of the stairway. Two paths lay before you, one left and one right.
You hear the sound of rushing water coming from the right passageway.

> go right

You head into the right passageway...
You find yourself alongside a great rushing underground river!
The remains of a broken bridge lie torn and rotted. You'll have to find some other way to cross.
There's a great root of some tree sticking out from the ceiling, but it's too high for you to reach.
The base of the steps lie behind you.

> throw rope

You throw with all your might, and the rope catches on the root! You swing across safely.
It looks like there was once a battle here, long ago. You see the remains of a knight, still clothed in armor. A slightly-rusted sword lies across his lap.

> take sword

Seems a shame to leave a fine sword to rust like that... It would be better off with you.
You picked up the sword.

> go back

You throw the rope again, and swing back to the other side.
You find yourself alongside a great rushing underground river!
The remains of a broken bridge lie torn and rotted. You'll have to find some other way to cross.
There's a great root of some tree sticking out from the ceiling, but it's too high for you to reach.
The base of the steps lie behind you.

> go back

You return to the base of the steps.
You are at the base of the stairway. Two paths lay before you, one left and one right.
You hear the sound of rushing water coming from the right passageway.

> go back

You go up the steps...
You find yourself at the top of a long stair descending downward. You cannot make out the bottom.
Behind you lies the great hall you first entered through.

> go back

You exit back into the hall you came through.
You find yourself in a central hall.
Through the gloom you barely make out three arches to ongoing passages: one left, one middle, and one right.

> go left

You pass through the left corridor...
You come upon a long hallway, the walls covered by thick webs. Thousands of little legs seem to scurry away from your torch's light.
You notice a door at the end of the hall, completely covered in webs. You'll need someting sharp to get cut through it.

> cut

The sword slices right through the webs! You're able to cut away the door and get through.
You come in to a small room with a glowing pedestal in the center.
The light is dazzling, and upon the pedestal lies an ornate key. Neat!

> take key

You slowly reach out your hand, wary of any traps you might spring, or eyes that might be watching...
...but there aren't any. Easy, right?
You picked up the key.

> go back

You exit back into the hall of spiders.
You return to the long hall, still covered in webs. The door is free, now, though. You feel like hundreds of tiny eyes are watching your every move.
The main hall lies behind you.

> go back

You exit back into the hall you first entered in.
You find yourself in a central hall.
Through the gloom you barely make out three arches to ongoing passages: one left, one middle, and one right.

> go middle

You pass through the middle corridor...
You find yourself at the top of a long stair descending downward. You cannot make out the bottom.
Behind you lies the great hall you first entered through.

> go down

You muster all of your courage and wander down into the depths...
You are at the base of the stairway. Two paths lay before you, one left and one right.
You hear the sound of rushing water coming from the right passageway.

> go left

You head into the left passageway...
You enter a small room, with stone close all around you. Before you lies a door sealed with a large lock.
Behind you lie the base of the steps.

> unlock

You fit the key into the lock, and slowly start to turn it...
It works! The lock falls away and you pass through the door.
It appears to be a dead end.

> reach through the crack in the rocks

What? What crack in the rocks?

> the crack in the rocks concealing the magical orb with the flag

There's a crack in the --? Well, it seems you know more about this world than I do. Happy hacking!
bctf{P33r_1nT0_tH3_j4r_2_f1nd_Th3_S3cR3Ts_d1463580a690f294}
```

## Flag

And that's the flag: `bctf{P33r_1nT0_tH3_j4r_2_f1nd_Th3_S3cR3Ts_d1463580a690f294}`
