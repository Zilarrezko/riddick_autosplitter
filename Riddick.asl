/* Contributers
                       ┌───────────┐
┌──────────────────────┤  Created  │
│    Jesse E Coyle     │ 7/18/2018 │
├──────────────────────┼───────────┤
│   JesseECoyle#2375   │  Discord  │
│ JesseCoyleE@gmail.com│   Email   │
└──────────────────────┴───────────┘
 */

// IMPORTANT: Sometimes things don't work. Just let me know

state("DarkAthena")
{
	// Note: Not working for others... I will look into a code injection to see if I can get this to work for everyone
	// string20 Map: "DarkAthena.exe", 0x0008A5F4, 0xA0, 0x18, 0x14, 0x3C, 0x18C;
	
	string20 MenuStateString: "DarkAthena.exe", 0x0008A5F4, 0xA0, 0x18, 0x14, 0x3C, 0x18C;
	
	// Note: This gametime tacs on most of the cutscene times, whether you skip them or not. Some cutscenes don't and special movie cutscenes
	//       like when you get your eyeshine do not add their time on. It does seem that some cutscenes add more time than they take, however.
	//  aka. Inconsistent and a hassle
	double GameTime: "GameClasses_Win32_x86.dll", 0x00849E68;
}

init
{	
	vars.Game = "";
	vars.Level = 0;
	
	vars.AoDAStartLatch = false;
	
	var MainModule = modules.First();
	print("[The Chronicles of Riddick] MainModule Found: " + MainModule);
	var GameWorldModule = modules.Where(m => m.ModuleName == "GameWorld_Win32_x86.dll").First();
	print("[The Chronicles of Riddick] GameWorldModule Found: " + GameWorldModule);
	var MainModuleSigScan = new SignatureScanner(game, MainModule.BaseAddress, MainModule.ModuleMemorySize);
	var GameWorldSigScan = new SignatureScanner(game, GameWorldModule.BaseAddress, GameWorldModule.ModuleMemorySize);
	print("[The Chronicles of Riddick] Sig Scan");
	vars.LoadFlagWriteCode = MainModuleSigScan.Scan(new SigScanTarget(0,
		0x83, 0x85, 0xB4, 0x12, 0x00, 0x00, 0x01  // Note: add dword ptr [ebp+000012B4], 01
	));
	vars.MapNameWriteCode = GameWorldSigScan.Scan(new SigScanTarget(0,
		0x8D, 0x56, 0x04,             // **Note: lea edx, [esi+04]
		0x8B, 0xC8,                   //   Note: mov ecx, eax
		0x2B, 0xD1                    //   Note: sub edx, ecx
	));
	// vars.MapNameWriteCode = (int)vars.MapNameWriteCode + 0x10;
	
	if((int)vars.LoadFlagWriteCode == 0)
	{ // Note: This will restart the init script so we can retry memory scanning
		throw new Exception("[The Chronicles of Riddick] Load flag writing code couldn't be found");
	}
	else
	{
		print("[The Chronicles of Riddick] Found where load flag is being written: 0x" + vars.LoadFlagWriteCode.ToString("X"));
	}
	if((int)vars.MapNameWriteCode == 0)
	{
		throw new Exception("[The Chronicles of Riddick] Map name writing code couldn't be found");
	}
	else
	{
		print("[The Chronicles of Riddick] Found where map name is being written: 0x" + vars.MapNameWriteCode.ToString("X"));
	}
	
	// Todo: Coagulate code within one memory allocation page
	vars.LoadingFlagInjectionBase = game.AllocateMemory(0x100);
	vars.IsLoadingBase = vars.LoadingFlagInjectionBase + 0x13;
	print("[The Chronicles of Riddick] LoadingFlag Injection Code at: 0x" + vars.LoadingFlagInjectionBase.ToString("X"));
	vars.MapNameInjectionBase = game.AllocateMemory(0x100);
	vars.MapNameBase = vars.MapNameInjectionBase + 0x13;
	print("[The Chronicles of Riddick] MapName Injection Code at: 0x" + vars.MapNameInjectionBase.ToString("X"));
	
	var CodeForLoadingFlagInjection = new List<byte>()
	{
		0x89, 0x2D, /*IsLoadingBase*/          // Note: mov [IsLoadingBase], ebp
		0x83, 0x85, 0xB4,0x12,0x00,0x00, 0x01, // Note: add dword ptr [ebp+000012B4], 01
		0x68, /*LoadFlagWriteCode*/            // Note: push [LoadFlagWriteCode] + 7
		0xC3,                                  // Note: ret
		0x00, 0x00, 0x00, 0x00  // Note: This is where IsLoadingBase pointer will be
	};
	CodeForLoadingFlagInjection.InsertRange( 2, BitConverter.GetBytes((int)vars.IsLoadingBase));
	CodeForLoadingFlagInjection.InsertRange(14, BitConverter.GetBytes((int)vars.LoadFlagWriteCode + 7));
	
	var JumpToLoadingFlagInjection = new List<byte>()
	{
		0x68, /*LoadingFlagInjectionBase*/ // Note: push [LoadingFlagInjectionBase]
		0xC3,                              // Note: ret
		0x90                               // Note: nop
	};
	JumpToLoadingFlagInjection.InsertRange(1, BitConverter.GetBytes((int)vars.LoadingFlagInjectionBase));
	
	var CodeForMapNameInjection = new List<byte>()
	{
		0x8D, 0x56, 0x04,               // Note: lea edx, [esi+04]
		0x89, 0x15, /*MapNameBase*/     // Note: mov [MapNameBase], edx
		0x8B, 0xC8,                     // Note: mov ecx, eax
		0x29, 0xCA,                     // Note: sub edx, ecx
		0x68, /*MapName injected code*/ // Note: push [MapNameInjectionBase]
		0xC3,                           // Note: ret
		0x00, 0x00, 0x00, 0x00 // Note: This will be where MapNameBase pointer will be
	};
	CodeForMapNameInjection.InsertRange( 5, BitConverter.GetBytes((int)vars.MapNameBase));
	CodeForMapNameInjection.InsertRange(14, BitConverter.GetBytes((int)vars.MapNameWriteCode + 7));
	
	var JumpToMapNameInjection = new List<byte>()
	{
		0x68, /*MapNameInjectionBase*/ // Note: push [MapNameInjectionBase]
		0xC3,                          // Note: ret
		0x90                           // Note: nop
	};
	JumpToMapNameInjection.InsertRange(1, BitConverter.GetBytes((int)vars.MapNameInjectionBase));
	
	game.Suspend();
	print("[The Chronicles of Riddick] Injecting...");
	game.WriteBytes((IntPtr)vars.LoadFlagWriteCode, JumpToLoadingFlagInjection.ToArray());
	game.WriteBytes((IntPtr)vars.LoadingFlagInjectionBase, CodeForLoadingFlagInjection.ToArray());
	game.WriteBytes((IntPtr)vars.MapNameWriteCode, JumpToMapNameInjection.ToArray());
	game.WriteBytes((IntPtr)vars.MapNameInjectionBase, CodeForMapNameInjection.ToArray());
	game.Resume();
	print("[The Chronicles of Riddick] I'm done, bro");
}

update
{
	if(vars.IsLoadingBase != null)
	{
		vars.BasePointer = memory.ReadValue<IntPtr>((IntPtr)vars.IsLoadingBase);
		current.IsLoading = memory.ReadValue<byte>((IntPtr)vars.BasePointer + 0x12B4);
		vars.BasePointer = memory.ReadValue<IntPtr>((IntPtr)vars.MapNameBase);
		current.Map = memory.ReadString((IntPtr)vars.BasePointer, 20);
	}
}

shutdown
{
	if(game != null)
	{
		var OriginalLoadingFlagCode = new List<byte>()
		{
			0x83, 0x85, 0xB4, 0x12, 0x00, 0x00, 0x01
		};
		var OriginalMapNameCode = new List<byte>()
		{
			0x8D, 0x56, 0x04, 0x8B, 0xC8, 0x2B, 0xD1
		};
		game.Suspend();
		game.WriteBytes((IntPtr)vars.LoadFlagWriteCode, OriginalLoadingFlagCode.ToArray());
		game.WriteBytes((IntPtr)vars.MapNameWriteCode, OriginalMapNameCode.ToArray());
		game.Resume();
		game.FreeMemory((IntPtr)vars.LoadingFlagInjectionBase);
		game.FreeMemory((IntPtr)vars.MapNameInjectionBase);
	}
}

startup
{
	settings.Add("EfBB", true, "Escape from Butcher Bay");
	settings.Add("EfBBCheckpoints", true, "Checkpoints", "EfBB");
	settings.Add("EfBBLevel2",  true, "The Arrival",                "EfBBCheckpoints"); // Note: After the dream sequence, right when the cutscene starts to play
	settings.Add("EfBBLevel3",  true, "Prison Yard",                "EfBBCheckpoints"); // Note: When you trigger the save in your cell after delousing
	settings.Add("EfBBLevel4",  true, "Aquila Territory",           "EfBBCheckpoints"); // Note: After the loading sequence when you enter Aquila Territory for the first time
	settings.Add("EfBBLevel5",  true, "Infirmary",                  "EfBBCheckpoints"); // Note: Once you enter the Infirmary after loading
	settings.Add("EfBBLevel6",  true, "Mainframe",                  "EfBBCheckpoints"); // Note: Once you enter the Mainframe after loading, before you drop down and interact with the mainframe
	settings.Add("EfBBLevel7",  true, "Prison Yard Riot",           "EfBBCheckpoints"); // Note: After killing the first riot guard, going up the elevator, and hitting the loading screen
	settings.Add("EfBBLevel8",  true, "The Pit",                    "EfBBCheckpoints"); // Note: After the loading screen when you enter the pit 
	settings.Add("EfBBLevel9",  true, "Pope Joe's Den",             "EfBBCheckpoints"); // Note: After your dialogue exchange in Pope Joe's Den
	settings.Add("EfBBLevel10", true, "Dark Tunnels",               "EfBBCheckpoints"); // Note: After getting your eyeshine
	settings.Add("EfBBLevel11", true, "Showers",                    "EfBBCheckpoints"); // Note: In the showers in Narc Land
	settings.Add("EfBBLevel12", true, "Guard Quarters",             "EfBBCheckpoints"); // Note: After getting an eye scan and head through the door to the next section before Abbott
	settings.Add("EfBBLevel13", true, "Abbott",                     "EfBBCheckpoints"); // Note: The save that's just before you open the door to shoot at Abbott
	settings.Add("EfBBLevel14", true, "Tower 17",                   "EfBBCheckpoints"); // Note: After Abbott in The Homebox and before you get into the elevator with that guy who can't chill
	settings.Add("EfBBLevel15", true, "Tower 17 Base",              "EfBBCheckpoints"); // Note: After the loading screen in the elevator
	settings.Add("EfBBLevel16", true, "Recreation Area",            "EfBBCheckpoints"); // Note: First corridor loading room before the sectioned off recreation area
	settings.Add("EfBBLevel17", true, "Feed Ward",                  "EfBBCheckpoints"); // Note: After the loading screen from recreation area to the feed ward
	settings.Add("EfBBLevel18", true, "Work Pass",                  "EfBBCheckpoints"); // Note: After the loading screen from recreation area to the work pass
	settings.Add("EfBBLevel19", true, "Mine Entrance",              "EfBBCheckpoints"); // Note: When you're ontop of the elevator after the loading screen and before you jump those two guys
	settings.Add("EfBBLevel20", true, "Security Checkpoint",        "EfBBCheckpoints"); // Note: Before you get to that part that you hate
	settings.Add("EfBBLevel21", true, "Upper Mines",                "EfBBCheckpoints"); // Note: Before running through the gauntlet, after the loading screen after that part you hate
	settings.Add("EfBBLevel22", true, "Cargo Transport",            "EfBBCheckpoints"); // Note: After the loading screen and before you jump down the box elevator and get the tranquilizer
	settings.Add("EfBBLevel23", true, "Mining Core",                "EfBBCheckpoints"); // Note: After the loading screen directly after getting the tranquilizer
	settings.Add("EfBBLevel24", true, "Security Research 1",        "EfBBCheckpoints"); // Note: When you're in the air duct and open the grate before you go on your riot guard parade
	settings.Add("EfBBLevel25", true, "Security Research 2",        "EfBBCheckpoints"); // Note: Before the room where you first get out of your mech
	settings.Add("EfBBLevel26", true, "Tower 19",                   "EfBBCheckpoints"); // Note: In the airduct just before you drop down on that one guy and take his card and before getting the bomb
	settings.Add("EfBBLevel27", true, "Container Router",           "EfBBCheckpoints"); // Note: When you jump on that container
	settings.Add("EfBBLevel28", true, "Cell Crash",                 "EfBBCheckpoints"); // Note: During the cutscene where your containment cell crashes before the xeno section
	settings.Add("EfBBLevel29", true, "Abandoned Equipment Center", "EfBBCheckpoints"); // Note: After you jump down the hole to the xeno section
	settings.Add("EfBBLevel30", true, "Central Storage",            "EfBBCheckpoints"); // Note: In the ducts after the loading screen after you power that drill
	settings.Add("EfBBLevel31", true, "Loading Docks",              "EfBBCheckpoints"); // Note: Before you enter the room with the container router track with that one guard and the small flood of xenos
	settings.Add("EfBBLevel32", true, "Fuel Transport",             "EfBBCheckpoints"); // Note: Right before you fight the first Heavy Guard
	settings.Add("EfBBLevel33", true, "Hanger",                     "EfBBCheckpoints"); // Note: Right After you fight the Heavy Guard and after the loading screen
	settings.Add("EfBBLevel34", true, "Exercise Area",              "EfBBCheckpoints"); // Note: When you get dropped out of cryostasis for the first time
	settings.Add("EfBBLevel35", true, "Cryo Pyramids",              "EfBBCheckpoints"); // Note: During the last cutscene after getting into the other guy's cryobed
	settings.Add("EfBBLevel36", true, "Facility Control",           "EfBBCheckpoints"); // Note: After the loading screen after the two assault droids and riot guard
	settings.Add("EfBBLevel37", true, "Corporate Office",           "EfBBCheckpoints"); // Note: After the loading screen after killing the Heavy Guard in the elevator
	settings.Add("EfBBLevel38", true, "Take Off Platform",          "EfBBCheckpoints"); // Note: After the loading screen in the second elevator
	
	settings.Add("EfBBExtras", false, "Extras", "EfBB");
	settings.Add("EfBBExtra1", false, "From Aquila Territory to Prison Yard",  "EfBBExtras"); // Note: Coming back from when you kill Rust
	settings.Add("EfBBExtra2", false, "From Mine Entrance to Workpass",        "EfBBExtras"); // Note: When you're on your way to Tower 19
	settings.Add("EfBBExtra3", false, "From Security Research 2 to Feed Ward", "EfBBExtras"); // Note: After you get out of the riot guard
	
	
	settings.Add("AoDA", true, "Assault on Dark Athena");
	settings.Add("AoDALevel2",  true,  "Cargo Bay",      "AoDA"); // Note: 
	settings.Add("AoDALevel3",  true,  "Celldecks",      "AoDA"); // Note: 
	settings.Add("AoDALevel4",  true,  "Crewquarters",   "AoDA"); // Note: 
	settings.Add("AoDALevel5",  true,  "Alternator",     "AoDA"); // Note: 
	// settings.Add("AoDALevel6",  false, "???",            "AoDA"); // Note: I didn't get this checkpoint? Can anyone find this checkpoint?
	settings.Add("AoDALevel6",  true,  "Red Alert",      "AoDA"); // Note: 
	settings.Add("AoDALevel7",  true,  "Data Pad",       "AoDA"); // Note: 
	settings.Add("AoDALevel8",  true,  "Main Decks",     "AoDA"); // Note: 
	settings.Add("AoDALevel9",  true,  "Dronemile",      "AoDA"); // Note: 
	settings.Add("AoDALevel10", true,  "Recycle",        "AoDA"); // Note: 
	settings.Add("AoDALevel11", true,  "Spacewalk",      "AoDA"); // Note: 
	settings.Add("AoDALevel12", true,  "Celldecks Riot", "AoDA"); // Note: 
	settings.Add("AoDALevel13", true,  "Hanger Bay",     "AoDA"); // Note: 
	settings.Add("AoDALevel14", true,  "Culvert",        "AoDA"); // Note: 
	settings.Add("AoDALevel15", true,  "Crash Site",     "AoDA"); // Note: 
	settings.Add("AoDALevel16", true,  "Bazaar",         "AoDA"); // Note: 
	settings.Add("AoDALevel17", true,  "New Venice",     "AoDA"); // Note: 
	settings.Add("AoDALevel18", true,  "Old Town",       "AoDA"); // Note: 
	settings.Add("AoDALevel19", true,  "Refinery",       "AoDA"); // Note: 
	settings.Add("AoDALevel20", true,  "Star Port",      "AoDA"); // Note: 
	settings.Add("AoDALevel21", true,  "Executive",      "AoDA"); // Note: 
}

start
{
	bool Result = false;
	
	if(settings["EfBB"] &&
	   current.Map == "pa1_thedream" &&
	   current.IsLoading == 0 && old.IsLoading == 1)
	{
		vars.Game = "EfBB";
		vars.Level = 1;
		Result = true;
	}
	
	if(settings["AoDA"] &&
	   current.Map == "nc_TheNightmare")
	{
		if(vars.AoDAStartLatch &&
	       current.GameTime > 40.0)
		{
			vars.Game = "AoDA";
			vars.Level = 1;
			vars.AoDAStartLatch = false;
			Result = true;
		}
		
		if(current.GameTime < 1.0)
		{
			vars.AoDAStartLatch = true;
		}
	}
	
	return Result;
}

isLoading
{
	// Note: Value is:
	//  1 - When loading or skipping a cutscene
	//  2 - When paused in some menu
	// >2 - When in other menus... I guess? Based on how far down a menu rabbit hole you are
	// So it's kind of like IsLoading... But also like an IsPaused or IsMenu
	return current.IsLoading == 1;
}

split
{
	bool Result = false;

	if(vars.Game != "EfBB" && vars.Game != "AoDA")
	{ // Note: For when they prefer to manually start the timer
		print("Setting the Game autoamtically");
		if(current.Map == "pa1_thedream")
		{
			vars.Game = "EfBB";
		}
		else if(current.Map == "nc_TheNightmare")
		{
			vars.Game = "AoDA";
		}
	}
	
	if(vars.Game == "EfBB" && settings["EfBB"])
	{
		if(current.Map != old.Map)
		{
			if(settings["EfBBCheckpoints"])
			{
				if(current.Map == "pa1_Arrival"       && vars.Level ==  2 - 1 ||
				   current.Map == "Pa1_PrisonArea"    && vars.Level ==  3 - 1 ||
				   current.Map == "pa1_aquila"        && vars.Level ==  4 - 1 ||
				   current.Map == "pa1_infirmary"     && vars.Level ==  5 - 1 ||
				   current.Map == "Pa1_MainFrame"     && vars.Level ==  6 - 1 ||
				   current.Map == "pa1_riot"          && vars.Level ==  7 - 1 ||
				   current.Map == "pa1_pit"           && vars.Level ==  8 - 1 ||
				   current.Map == "pa1_popejoe"       && vars.Level ==  9 - 1 ||
				   current.Map == "pa1_nightvision"   && vars.Level == 10 - 1 ||
				   current.Map == "i1_showers"        && vars.Level == 11 - 1 ||
				   current.Map == "i1_pigsville"      && vars.Level == 12 - 1 ||
				   current.Map == "i1_abbott"         && vars.Level == 13 - 1 ||
				   current.Map == "pa2_t17"           && vars.Level == 14 - 1 ||
				   current.Map == "pa2_t17_base"      && vars.Level == 15 - 1 ||
				   current.Map == "pa2_courtyard"     && vars.Level == 16 - 1 ||
				   current.Map == "pa2_diner"         && vars.Level == 17 - 1 ||
				   current.Map == "pa2_workpass"      && vars.Level == 18 - 1 ||
				   current.Map == "pa2_m_rift"        && vars.Level == 19 - 1 ||
				   current.Map == "pa2_m_entrance"    && vars.Level == 20 - 1 ||
				   current.Map == "pa2_m_upper"       && vars.Level == 21 - 1 ||
				   current.Map == "pa2_Transport"     && vars.Level == 22 - 1 ||
				   current.Map == "pa2_m_lower"       && vars.Level == 23 - 1 ||
				   current.Map == "pa2_srf1"          && vars.Level == 24 - 1 ||
				   current.Map == "pa2_srf2"          && vars.Level == 25 - 1 ||
				   current.Map == "pa2_T19"           && vars.Level == 26 - 1 ||
				   current.Map == "pa2_rail"          && vars.Level == 27 - 1 ||
				   current.Map == "pa2_cellcrash"     && vars.Level == 28 - 1 ||
				   current.Map == "pa2_lair"          && vars.Level == 29 - 1 ||
				   current.Map == "pa2_m_exit"        && vars.Level == 30 - 1 ||
				   current.Map == "pa2_Prisonexit"    && vars.Level == 31 - 1 ||
				   current.Map == "pa2_fueltransport" && vars.Level == 32 - 1 ||
				   current.Map == "pa2_hangar"        && vars.Level == 33 - 1 ||
				   current.Map == "pa3_recarea"       && vars.Level == 34 - 1 ||
				   current.Map == "pa3_cryopyramids"  && vars.Level == 35 - 1 ||
				   current.Map == "pa3_powershutdown" && vars.Level == 36 - 1 ||
				   current.Map == "pa3_corpoffice"    && vars.Level == 37 - 1 ||
				   current.Map == "pa3_finalbattle"   && vars.Level == 38 - 1)
				{
					vars.Level++;

					Result = settings["EfBBLevel" + vars.Level];
				}
			}
			
			if(settings["EfBBExtras"])
			{
				if(current.Map == "pa1_prisonarea" && old.Map == "pa1_aquila")
				{
					Result = settings["EfBBExtra1"];
				}
				else if(current.Map == "pa2_workpass" && old.Map == "pa2_m_rift")
				{
					Result = settings["EfBBExtra2"];
				}
				else if(current.Map == "pa2_workpass" && old.Map == "pa2_srf2")
				{
					Result = settings["EfBBExtra3"];
				}
			}
		}
	}
	else if(vars.Game == "AoDA" && settings["AoDA"])
	{
		if(current.Map != old.Map)
		{
			if(current.Map == "Nc_CargoBay"     && vars.Level ==  2 - 1 ||
			   current.Map == "Nc_CellDecks"    && vars.Level ==  3 - 1 ||
			   current.Map == "NC_CrewQuarters" && vars.Level ==  4 - 1 ||
			   current.Map == "Nc_Alternator"   && vars.Level ==  5 - 1 ||
			   current.Map == "NC_RedAlert"     && vars.Level ==  6 - 1 ||
			   current.Map == "NC_celldecks"    && vars.Level ==  7 - 1 ||
			   current.Map == "NC_MainDecks"    && vars.Level ==  8 - 1 ||
			   current.Map == "Nc_DroneMile"    && vars.Level ==  9 - 1 ||
			   current.Map == "NC_Recycle"      && vars.Level == 10 - 1 ||
			   current.Map == "Nc_SpaceWalk"    && vars.Level == 11 - 1 ||
			   current.Map == "NC_CellDecks"    && vars.Level == 12 - 1 ||
			   current.Map == "Nc_HangarBay"    && vars.Level == 13 - 1 ||
			   current.Map == "NC_Culvert"      && vars.Level == 14 - 1 ||
			   current.Map == "Nc_Crashsite"    && vars.Level == 15 - 1 ||
			   current.Map == "nc_bazaar"       && vars.Level == 16 - 1 ||
			   current.Map == "NC_NewVenice"    && vars.Level == 17 - 1 ||
			   current.Map == "Nc_OldTown"      && vars.Level == 18 - 1 ||
			   current.Map == "Nc_Refinery"     && vars.Level == 19 - 1 ||
			   current.Map == "NC_Starport"     && vars.Level == 20 - 1 ||
			   current.Map == "Nc_Executive"    && vars.Level == 21 - 1)
			{
				vars.Level++;
				
				Result = settings["AoDALevel" + vars.Level];
			}
		}
	}
	
	return Result;
}

reset
{
	return current.MenuStateString == "Menu_GotCheckpoint";
}


// Note: Any% Route's Levels
// EfBB
//     pa1_intro         - Intro cutscene
//     pa1_thedream      - First part where you can control your character
//     pa1_Arrival       - Start of cutscene after the dream. Goes on until the after you're in your cell
//     Pa1_PrisonArea    - In cell after loading screen
//     pa1_aquila        - Loading screen into Aquila territory
//     pa1_prisonarea    - Returning to PrisonArea
//     pa1_infirmary     - 
//     Pa1_MainFrame     - 
//     pa1_riot          - 
//     pa1_pit           - 
//     pa1_popejoe       - The loading screen before the first elevator ride
//     pa1_nightvision   - After eyeshine
//     i1_showers        - 
//     i1_pigsville      - 
//     i1_abbott         - 
//     pa2_intro         - Cutscene of Johns getting 22% and you go to Tower 17
//     pa2_t17           - First curscene after that last one, of the home box
// ┌───pa2_t17_base      - 
// │┌──pa2_courtyard     - Recreation
// ││┌─pa2_diner         - Feedward
// │├──■                 - 
// └───■                 - Fight Basiim
//  ├──■                 - Going to get smack from two tongue
//┌─│┴─■                 - Fight Abbott
//│ └──■                 - On way to workpass
//│┌───pa2_workpass      - 
//││┌──pa2_m_rift        - After loading screen on top of elevator
//│││  pa2_m_entrance    - Security Checkpoint, riot guard
//│││  pa2_m_upper       - Gauntlet
//│││┌─pa2_Transport     - Box Transport before you get the tranq gun
//││││ pa2_m_lower       - The second gauntlet, with the riot guard
//│││└─■                 - Take the cargo transport all the way up
//││└──■                 - Use the vent tool and use the shortcut to the elevator
//│├───■                 - 
//││   pa2_srf1          - Security Research Facility
//││   pa2_srf2          - That loading screen before the room where you first get out of your riot guard
//│└───■                 - Possible skip? ~2-3 or so minute time save
//└────■                 - 
//     pa2_T19           - 
//     pa2_rail          - 
//     Pa2_M_Lower       - This is when you're coming back to plant the bomb... Since this isn't part of the checkpoints we don't count it
//     pa2_cellcrash     - Start of Cutscene
//     pa2_lair          - 
//     pa2_m_exit        - 
//     pa2_Prisonexit    - 
//     pa2_fueltransport - Heavy Guard boss
//     pa2_hangar        - 
//     pa3_recarea       - 
//     pa3_cryopyramids  - 
//     pa3_powershutdown - 
//     pa3_corpoffice    - 
//     pa3_finalbattle   - Second Elevator in a Heavy Guard
//

// Note: Any% Route's Levels
// AoDA
// Note '*' indicates there's a checkpoint there
//    nc_TheNightmare    - *
//    Nc_Intro           - 
//    Nc_CargoBay        - *
//    Nc_CellDecks       - *
//    NC_CrewQuarters    - *
//    NC_Celldecks       - 
//    Nc_Alternator      - *
//    Nc_CellDecks       - 
//    NC_RedAlert        - *
//    NC_celldecks       - *
//    NC_MainDecks       - *
//    Nc_DroneMile       - *
//    NC_Recycle         - *
//    Nc_SpaceWalk       - *
//    NC_CellDecks       - *
//    Nc_HangarBay       - *
//    NC_Culvert         - *
//    Nc_Crashsite       - *
//    nc_bazaar          - *
//    NC_NewVenice       - *
//    Nc_OldTown         - *
//    Nc_Refinery        - *
//    NC_Starport        - *
//    Nc_Executive       - *
//    
