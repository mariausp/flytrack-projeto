# core/views.py
from django.shortcuts import render
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, EmailMessage, BadHeaderError
from django.conf import settings
from django.http import HttpResponse
from .forms import SignupForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
import textwrap

def home(request):
    return render(request, 'home.html')

def resultados(request):
    return render(request, 'resultados.html')

def historico(request):
    return render(request, 'historico.html')

def contato(request):
    context = {"errors": {}, "data": {}}
    if request.method == "POST":
        nome = request.POST.get("nome", "").strip()
        email = request.POST.get("email", "").strip()
        assunto = request.POST.get("assunto", "").strip()
        mensagem = request.POST.get("mensagem", "").strip()

        context["data"] = {"nome": nome, "email": email, "assunto": assunto, "mensagem": mensagem}

        if not nome:
            context["errors"]["nome"] = "Informe seu nome."
        if not email:
            context["errors"]["email"] = "Informe seu e-mail."
        else:
            try:
                validate_email(email)
            except ValidationError:
                context["errors"]["email"] = "E-mail inválido."
        if not assunto:
            context["errors"]["assunto"] = "Informe um assunto."
        if not mensagem or len(mensagem) < 10:
            context["errors"]["mensagem"] = "Escreva uma mensagem (mínimo 10 caracteres)."

        if not context["errors"]:
            try:
                corpo_admin = textwrap.dedent(f"""
                Nova mensagem de contato no FlyTrack:

                Nome: {nome}
                E-mail: {email}
                Assunto: {assunto}

                Mensagem:
                {mensagem}
                """)
                EmailMessage(
                    subject=f"[FlyTrack] Contato: {assunto}",
                    body=corpo_admin,
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    to=[getattr(settings, "CONTACT_TO_EMAIL", settings.EMAIL_HOST_USER)],
                    reply_to=[email] if email else None,
                ).send(fail_silently=False)

                # resposta opcional ao usuário
                send_mail(
                    subject="Recebemos sua mensagem — FlyTrack",
                    message=textwrap.dedent(f"Olá, {nome}!\n\nRecebemos sua mensagem e responderemos em breve.\n\nAssunto: {assunto}\n\n— Equipe FlyTrack"),
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    recipient_list=[email],
                    fail_silently=True,
                )

                context["success"] = True
                context["data"] = {}
            except BadHeaderError:
                context["errors"]["assunto"] = "Assunto inválido."
            except Exception:
                # era: context["errors"]["__all__"] = ...
                context["errors"]["global"] = "Não foi possível enviar sua mensagem agora. Tente novamente mais tarde."

    return render(request, 'contato.html', context)

def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Conta criada com sucesso. Você já está logada.")
            # auto login após cadastro
            login(request, user)
            return redirect("core:home")  # ajuste para a rota que preferir
        else:
            # form.errors vai para template
            pass
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})

def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"Olá {user.get_full_name() or user.username} — você entrou.")
                return redirect("core:home")
            else:
                messages.error(request, "Usuário ou senha inválidos.")
        else:
            messages.error(request, "Usuário ou senha inválidos.")
    else:
        form = AuthenticationForm()
    return render(request, "registration/login.html", {"form": form})

def logout_view(request):
    logout(request)
    messages.info(request, "Você saiu da conta.")
    return redirect("core:home")
