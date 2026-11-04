#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Focus only the owned VS Code process's viewable Xvfb window, without a window manager."""
import ctypes as C
import os
import sys

pid=int(sys.argv[1]);assert pid>1
x=C.CDLL('libX11.so.6');display=C.c_void_p;window=C.c_ulong
class Attributes(C.Structure):
    _fields_=[('x',C.c_int),('y',C.c_int),('width',C.c_int),('height',C.c_int),('border',C.c_int),('depth',C.c_int),('visual',C.c_void_p),('root',window),('kind',C.c_int),('bit_gravity',C.c_int),('win_gravity',C.c_int),('backing_store',C.c_int),('backing_planes',C.c_ulong),('backing_pixel',C.c_ulong),('save_under',C.c_int),('colormap',C.c_ulong),('map_installed',C.c_int),('map_state',C.c_int),('all_masks',C.c_long),('your_mask',C.c_long),('propagate_mask',C.c_long),('override',C.c_int),('screen',C.c_void_p)]
x.XOpenDisplay.argtypes=[C.c_char_p];x.XOpenDisplay.restype=display
x.XDefaultRootWindow.argtypes=[display];x.XDefaultRootWindow.restype=window
x.XQueryTree.argtypes=[display,window,C.POINTER(window),C.POINTER(window),C.POINTER(C.POINTER(window)),C.POINTER(C.c_uint)]
x.XInternAtom.argtypes=[display,C.c_char_p,C.c_int];x.XInternAtom.restype=C.c_ulong
x.XGetWindowProperty.argtypes=[display,window,C.c_ulong,C.c_long,C.c_long,C.c_int,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.POINTER(C.c_ubyte))]
x.XGetWindowAttributes.argtypes=[display,window,C.POINTER(Attributes)]
x.XSetInputFocus.argtypes=[display,window,C.c_int,C.c_ulong]
x.XFlush.argtypes=[display];x.XCloseDisplay.argtypes=[display];x.XFree.argtypes=[C.c_void_p]
d=x.XOpenDisplay(os.environ['DISPLAY'].encode())
if not d: raise SystemExit(1)
try:
    root=x.XDefaultRootWindow(d);r=window();parent=window();children=C.POINTER(window)();count=C.c_uint()
    if not x.XQueryTree(d,root,C.byref(r),C.byref(parent),C.byref(children),C.byref(count)): raise SystemExit(1)
    atom=x.XInternAtom(d,b'_NET_WM_PID',1);found=[]
    try:
        for i in range(count.value):
            actual=C.c_ulong();fmt=C.c_int();items=C.c_ulong();after=C.c_ulong();data=C.POINTER(C.c_ubyte)();attrs=Attributes()
            result=x.XGetWindowProperty(d,children[i],atom,0,1,0,0,C.byref(actual),C.byref(fmt),C.byref(items),C.byref(after),C.byref(data))
            try:
                if result==0 and fmt.value==32 and items.value==1 and C.cast(data,C.POINTER(C.c_ulong))[0]==pid and x.XGetWindowAttributes(d,children[i],C.byref(attrs)) and attrs.map_state==2 and attrs.width>300 and attrs.height>200:
                    found.append(children[i])
            finally:
                if data: x.XFree(data)
    finally:
        if children: x.XFree(children)
    if len(found)!=1: raise SystemExit(1)
    x.XSetInputFocus(d,found[0],2,0);x.XFlush(d)
finally: x.XCloseDisplay(d)
