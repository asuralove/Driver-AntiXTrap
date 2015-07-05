#ifndef  ___HOOK_SHADOWSSDT_IO_CONTROL___ 
#define	 ___HOOK_SHADOWSSDT_IO_CONTROL___ 
 

/************************************************************************ 
*                                                                      * 
*                             Struct Define                            * 
*                                                                      * 
************************************************************************/  
 
typedef struct ServiceDescriptorEntry { 
	PVOID *ServiceTableBase; 
	ULONG *ServiceCounterTableBase; //Used only in checked build 
	ULONG NumberOfServices; 
	PVOID *ParamTableBase; 
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry; 
 
PServiceDescriptorTableEntry KeServiceDescriptorTableShadow;
 
#endif