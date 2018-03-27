#include "RemoveCallBack.h"

VOID EnableObType(POBJECT_TYPE ObjectType, BOOLEAN enable)
{
	PMY_OBJECT_TYPE myobtype = (PMY_OBJECT_TYPE)ObjectType;
	if (enable)
		myobtype->TypeInfo.SupportsObjectCallbacks = 1;
	else
		myobtype->TypeInfo.SupportsObjectCallbacks = 0;
}
