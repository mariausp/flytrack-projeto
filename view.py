from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, EmailMessage, BadHeaderError
from django.conf import settings
from django.http import Http404
from django.utils import timezone
from django.db.models import Q
from django.utils.dateparse import parse_date
import hashlib, secrets, datetime, textwrap
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Imports locais (ATUALIZADOS)
from .forms import SignupForm, ForgotPasswordForm, ResetPasswordForm, VooAdminForm
from .models import PasswordResetToken, Ticket, Voo

User = get_user_model()

# ---------------------- HISTÓRICO ----------------------
@login_required
def historico(request):
    qs = Ticket.objects.filter(user=request.user).order_by('-partida')

    q = (request.GET.get('q') or '').strip()
    status = (request.GET.get('status') or '').strip().upper()
    dfrom = request.GET.get('from') or ''
    dto   = request.GET.get('to') or ''

    if q:
        qs = qs.filter(
            Q(codigo__icontains=q) |
            Q(origem__icontains=q) |
            Q(destino__icontains=q)
        )

    if status:
        qs = qs.filter(status=status)

    if dfrom:
        df = parse_date(dfrom)
        if df:
            qs = qs.filter(partida__date__gte=df)

    if dto:
        dt = parse_date(dto)
        if dt:
            qs = qs.filter(partida__date__lte=dt)

    from django.core.paginator import Paginator
    paginator = Paginator(qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    ctx = {
        'tickets': page_obj.object_list,
        'page_obj': page_obj,
        'total': qs.count(),
    }
    return render(request, "historico.html", ctx)

# ---------------------- PÁGINAS GERAIS ----------------------
def home(request):
    return render(request, "home.html")

def resultados(request):
    return render(request, "resultados.html")

def contato(request):
    context = {"errors": {}, "data": {}}
    if request.method == "POST":
        nome = request.POST.get("nome", "").strip()
        email = request.POST.get("email", "").strip()
        assunto = request.POST.get("assunto", "").strip()
        mensagem = request.POST.get("mensagem", "").strip()
        context["data"] = {"nome": nome, "email": email, "assunto": assunto, "mensagem": mensagem}

        if not nome: context["errors"]["nome"] = "Informe seu nome."
        if not email:
            context["errors"]["email"] = "Informe seu e-mail."
        else:
            try: validate_email(email)
            except ValidationError: context["errors"]["email"] = "E-mail inválido."
        
        if not assunto: context["errors"]["assunto"] = "Informe um assunto."
        if not mensagem or len(mensagem) < 10:
            context["errors"]["mensagem"] = "Escreva uma mensagem (mínimo 10 caracteres)."

        if not context["errors"]:
            try:
                send_mail(
                    f"[FlyTrack] {assunto}",
                    f"Nome: {nome}\nEmail: {email}\n\n{mensagem}",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.CONTACT_TO_EMAIL],
                    fail_silently=True,
                )
                messages.success(request, "Mensagem enviada com sucesso!")
                context["data"] = {}
            except Exception:
                messages.error(request, "Erro ao enviar mensagem.")
    
    return render(request, "contato.html", context)

# ---------------------- AUTH ----------------------
def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f"Bem-vindo, {user.username}!")
            return redirect("core:home")
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})

def login_view(request):
    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            login(request, form.get_user())
            return redirect("core:home")
    return render(request, "registration/login.html", {"form": form})

def logout_view(request):
    logout(request)
    return redirect("core:home")

@login_required
def post_login(request):
    if request.user.is_staff:
        return redirect("core:admin_home")
    return redirect("core:home")

# ---------------------- ADMIN / STAFF ----------------------
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_home(request):
    return render(request, "admin/adm_home.html")

# === FUNÇÃO ATUALIZADA (PASSO 4) ===
@login_required
@user_passes_test(lambda u: u.is_staff)
def adicionar_passagem(request):
    # 1. Busca todos os voos já cadastrados (do mais novo para o mais antigo)
    voos_disponiveis = Voo.objects.all().order_by('-criado_em')

    if request.method == 'POST':
        form = VooAdminForm(request.POST)
        if form.is_valid():
            voo = form.save()
            messages.success(request, f"Voo {voo.codigo} cadastrado e disponível para venda!")
            return redirect('core:adicionar_passagem') # Recarrega a mesma página para ver a tabela atualizada
    else:
        form = VooAdminForm()
    
    # 2. Enviamos a lista 'voos_disponiveis' para o HTML junto com o formulário
    return render(request, 'admin/adicionar_passagem.html', {
        'form': form, 
        'voos': voos_disponiveis
    })

# ---------------------- SENHA ----------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def forgot_password(request):
    if request.method == "POST":
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = User.objects.get(email__iexact=email)
                messages.success(request, "Se o e-mail existir, enviamos um link.")
            except User.DoesNotExist:
                pass
            return redirect("core:password_reset_done")
    else:
        form = ForgotPasswordForm()
    return render(request, "password_reset.html", {"form": form})

def reset_password_done(request): return render(request, "password_reset_done.html")
def reset_password_confirm(request, uidb64, token): return render(request, "password_reset_confirm.html")
def reset_password_complete(request): return render(request, "password_reset_complete.html")
