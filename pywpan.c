/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the MIT License.
 * See the file LICENSE in the top level directory for more details.
 */

#define PY_SSIZE_T_CLEAN    /* always use Py_ssize_t instead of int for string parsing */
#include <Python.h>
#include <endian.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>

#define PyWPAN_MODULE_NAME "pywpan"
#define PyWPAN_ADDR_NONE    (0)
#define PyWPAN_ADDR_SHORT   (2)
#define PyWPAN_ADDR_LONG    (3)

#define IEEE802154_ADDR_LEN (8)
#define MAX_PACKET_LEN      (127)

typedef struct {
    PyObject_HEAD
    int sock_fd;                /* Socket file descriptor */
} PyWPANSocketObject;

struct sockaddr_ieee802154 {
    sa_family_t family;
    int addr_type;
    uint16_t pan_id;
    union {
        uint8_t along[IEEE802154_ADDR_LEN];
        uint16_t ashort;
    } addr;
};

static int PyWPANSocket_init(PyWPANSocketObject *self, PyObject *args, PyObject *kwds);
static void PyWPANSocket_dealloc(PyWPANSocketObject *self);
static PyObject *PyWPANSocket_bind(PyWPANSocketObject *self, PyObject *addr);
static PyObject *PyWPANSocket_sendto(PyWPANSocketObject *self, PyObject *addr);
static PyObject *PyWPANSocket_recvfrom(PyWPANSocketObject *self);

static PyMethodDef PyWPANSocket_methods[] = {
    {"bind", (PyCFunction)PyWPANSocket_bind, METH_O, 0},
    {"sendto", (PyCFunction)PyWPANSocket_sendto, METH_VARARGS, 0},
    {"recvfrom", (PyCFunction)PyWPANSocket_recvfrom, METH_NOARGS, 0},
    /* {"get_hwaddr", (PyCFunction)PyWPANSocket_get_hwaddr, METH_NOARGS, 0}, */
    {NULL}  /* Sentinel */
};

static PyTypeObject PyWPANSocketType = {
    PyVarObject_HEAD_INIT(NULL, 0)      /* semi-colon intentially missing */
    PyWPAN_MODULE_NAME ".socket",       /* tp_name */
    sizeof(PyWPANSocketObject),         /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)PyWPANSocket_dealloc,   /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,            /* tp_flags */
    0,                                  /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    PyWPANSocket_methods,               /* tp_methods */
    0,                                  /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)PyWPANSocket_init,        /* tp_init */
    PyType_GenericAlloc,                /* tp_alloc */
    PyType_GenericNew,                  /* tp_new */
};

PyObject *moduleinit(PyObject *m)
{
    if (m == NULL) {
        return NULL;
    }
    if (PyModule_AddIntConstant(m, "ADDR_NONE", PyWPAN_ADDR_NONE) == -1) {
        return NULL;
    }
    if (PyModule_AddIntConstant(m, "ADDR_SHORT", PyWPAN_ADDR_SHORT) == -1) {
        return NULL;
    }
    if (PyModule_AddIntConstant(m, "ADDR_LONG", PyWPAN_ADDR_LONG) == -1) {
        return NULL;
    }
    if (PyType_Ready(&PyWPANSocketType) < 0) {
        return NULL;
    }
    Py_INCREF(&PyWPANSocketType);
    if (PyModule_AddObject(m, "socket", (PyObject *)(&PyWPANSocketType)) == -1) {
        return NULL;
    }
    return m;
}

#if PY_MAJOR_VERSION < 3
#error "Python<3 currently not supported."
#else
struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    PyWPAN_MODULE_NAME,              /* m_name */
    NULL,                            /* m_doc */
    -1,                              /* m_size */
    NULL,                            /* m_methods */
    NULL,                            /* m_reload */
    NULL,                            /* m_traverse */
    NULL,                            /* m_clear */
    NULL,                            /* m_free */
};

PyMODINIT_FUNC PyInit_pywpan(void)
{
    PyObject* m;
    m = PyModule_Create(&moduledef);
    return moduleinit(m);
}
#endif

static PyObject *get_addr_from_args(PyObject *addr, struct sockaddr_ieee802154 *so)
{
    PyObject *addro;
    char *addr_str;
    long int pan_id;

    if ((addr == NULL) || !PyTuple_Check(addr) || (PyTuple_GET_SIZE(addr) != 2)) {
        PyErr_SetString(PyExc_ValueError, "addr parameter must be a tuple of size 2.");
        return NULL;
    }

    pan_id = PyLong_AsLong(PyTuple_GET_ITEM(addr, 0));
    addro = PyTuple_GET_ITEM(addr, 1);

    if ((pan_id < 0x0000) || (pan_id > 0xffff)) {
        PyErr_Format(PyExc_ValueError, "first element of addr must be between 0 and %u",
                     0xffff);
        return NULL;
    }
    Py_INCREF(addro);
    so->family = AF_IEEE802154;
    so->pan_id = htole16((uint16_t)pan_id);
    if ((addro == Py_None)) {
        so->addr_type = PyWPAN_ADDR_NONE;
    }
    else if (PyLong_Check(addro)) {
        long int addr_int = PyLong_AsLong(addro);
        if ((addr_int < 0x0000) || (addr_int > 0xffff)) {
            PyErr_SetString(PyExc_ValueError,
                            "second element should be short address but value would overflow");
            return NULL;
        }
        so->addr_type = PyWPAN_ADDR_SHORT;
        so->addr.ashort = htole16((uint16_t)addr_int);
    }
    else if (!PyBytes_Check(addro)) {
        Py_DECREF(addro);
        PyErr_SetString(PyExc_ValueError,
                        "second element of addr must be of type bytes, int or None");
        return NULL;
    }
    else {
        switch (PyBytes_Size(addro)) {
            case 0:
                so->addr_type = PyWPAN_ADDR_NONE;
                break;
            case 2: {
                uint16_t addr16;

                addr_str = PyBytes_AsString(addro);
                addr16 = (addr_str[0] << 8) | (addr_str[1]);
                so->addr.ashort = htole16(addr16);
                so->addr_type = PyWPAN_ADDR_SHORT;
                break;
            }
            case 8:
                addr_str = PyBytes_AsString(addro);
                memcpy(&so->addr, addr_str, 8);
                so->addr_type = PyWPAN_ADDR_LONG;
                break;
            default:
                Py_DECREF(addro);
                PyErr_SetString(PyExc_ValueError, "second element must be of length 0, 2 or 8");
                return NULL;
        }
    }
    Py_DECREF(addro);
    return addr;
}

static int PyWPANSocket_init(PyWPANSocketObject *self, PyObject *args, PyObject *kwds)
{
    int res = socket(AF_IEEE802154, SOCK_DGRAM, 0);

    if (res < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    self->sock_fd = res;
    return 0;
}

static void PyWPANSocket_dealloc(PyWPANSocketObject *self)
{
    close(self->sock_fd);
}

static PyObject *PyWPANSocket_bind(PyWPANSocketObject *self, PyObject *addr)
{
    PyErr_SetString(PyExc_NotImplementedError, "bind() not implemented yet");
    return NULL;
}

static PyObject *PyWPANSocket_sendto(PyWPANSocketObject *self, PyObject *args)
{
    PyObject *addr;
    const char *buf;
    Py_ssize_t bufsize;
    ssize_t res;
    struct sockaddr_ieee802154 sa;

    /* parse python arguments [str/bytes+ssize_t, object] */
    if (!PyArg_ParseTuple(args, "s#O", &buf, &bufsize, &addr)) {
        return NULL;
    }
    if (!get_addr_from_args(addr, &sa)) {
        return NULL;
    }
    if ((res = sendto(self->sock_fd, buf, bufsize, 0, (struct sockaddr *)&sa,
                      sizeof(sa))) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyLong_FromSsize_t(res);
}

static PyObject *PyWPANSocket_recvfrom(PyWPANSocketObject *self)
{
    PyErr_SetString(PyExc_NotImplementedError, "recvfrom() not implemented yet");
    return NULL;
}
