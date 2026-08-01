from django import template
from django.utils.safestring import mark_safe

register = template.Library()

_TYPES = {
    'pdf': ('PDF', 'bg-red-500'),
    'image': ('IMG', 'bg-sky-500'),
    'video': ('VID', 'bg-violet-500'),
    'audio': ('AUD', 'bg-orange-400'),
    'zip': ('ZIP', 'bg-amber-500'),
    'doc': ('DOC', 'bg-blue-600'),
    'xls': ('XLS', 'bg-emerald-500'),
    'ppt': ('PPT', 'bg-orange-500'),
    'text': ('TXT', 'bg-green-500'),
    'code': ('CODE', 'bg-slate-600'),
    'file': ('FILE', 'bg-gray-400'),
}

@register.filter
def file_icon(mime_type):
    """Map a MIME type to a small colored label badge for fast scanning."""
    mime = (mime_type or '').lower()
    label, color = _TYPES['file']
    if mime == 'application/pdf':
        label, color = _TYPES['pdf']
    elif mime.startswith('image/'):
        label, color = _TYPES['image']
    elif mime.startswith('video/'):
        label, color = _TYPES['video']
    elif mime.startswith('audio/'):
        label, color = _TYPES['audio']
    elif 'zip' in mime or 'compress' in mime or 'archive' in mime or 'rar' in mime or 'tar' in mime:
        label, color = _TYPES['zip']
    elif 'wordprocessingml' in mime or mime == 'application/msword':
        label, color = _TYPES['doc']
    elif 'spreadsheetml' in mime or 'excel' in mime or mime == 'application/vnd.ms-excel':
        label, color = _TYPES['xls']
    elif 'presentationml' in mime or 'powerpoint' in mime or mime == 'application/vnd.ms-powerpoint':
        label, color = _TYPES['ppt']
    elif mime.startswith('text/'):
        label, color = _TYPES['text']
    elif 'json' in mime or 'javascript' in mime or 'xml' in mime or 'html' in mime or 'css' in mime or 'x-python' in mime or 'x-sh' in mime:
        label, color = _TYPES['code']
    return mark_safe(
        '<span class="w-9 h-9 border-[2.5px] border-[#0A0A0A] %s text-white text-[10px] font-bold '
        'flex items-center justify-center flex-shrink-0">%s</span>' % (color, label)
    )
