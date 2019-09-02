using AutoMapper;
using FluentValidation;
using FluentValidation.AspNetCore;
using iNube.Services.UserManagement.Controllers.Controllers.Permission.PermissionService.MicaPermission;
using iNube.Services.UserManagement.Controllers.Controllers.Permission.PermissionService.MotorPermission;
using iNube.Services.UserManagement.Controllers.Login.LoginServices;
using iNube.Services.UserManagement.Controllers.Login.LoginServices.MicaLogin;
using iNube.Services.UserManagement.Controllers.Login.LoginServices.MotorLogin;
using iNube.Services.UserManagement.Controllers.Permission.PermissionService;
using iNube.Services.UserManagement.Controllers.Role.RoleService;
using iNube.Services.UserManagement.Controllers.Role.RoleService.MicaRole;
using iNube.Services.UserManagement.Controllers.Role.RoleService.MotorRole;
using iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService;
using iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService.MicaProfile;
using iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService.MotorProfile;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Entities.AVO;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Services.UserManagement.Validations;
using iNube.Utility.Framework.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Serialization;
using System;

namespace iNube.Services.UserManagement
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<MICAUMContext>();

            ////services.AddDbContext<MICAUMContext>(x => x.UseSqlServer(connectionstring));

            //////AVO
            var avoConnectionstring = Configuration.GetConnectionString("AVOUMConnection");
            services.AddDbContext<AVOUMContext>(x => x.UseSqlServer(avoConnectionstring));

            // configure strongly typed settings objects
            var appSettingsSection = Configuration.GetSection("AppSettings");
            services.Configure<AppSettings>(appSettingsSection);

            //Module service
            ConfigureModuleService(services);

            //Common Service
            services.InitializedCommonServices(Configuration);

            services.AddMvc()
           .AddFluentValidation(options =>
           {
               options.RegisterValidatorsFromAssemblyContaining<Startup>();
           });

            //services.AddMvcCore()
            //.AddAuthorization() // Note - this is on the IMvcBuilder, not the service collection
            //.AddJsonFormatters(options => options.ContractResolver = new CamelCasePropertyNamesContractResolver())
            //.AddFluentValidation(options =>
            // {
            //     options.RegisterValidatorsFromAssemblyContaining<Startup>();
            // });

            var connectionstring = Configuration.GetConnectionString("UMConnection");
            services.AddHealthChecks().AddSqlServer(connectionstring);
            services.AddAutoMapper(typeof(Startup));


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.InitializedCommonConfiguration(env, Configuration);
            // app.ConfigureExceptionHandler(new LoggerManager());
            app.UseAuthentication();
        }

        private void ConfigureModuleService(IServiceCollection services)
        {
            // configure DI for application services
            services.AddTransient<IValidator<UserDTO>, CreateProfileUserRequestValidator>();
            services.AddTransient<IValidator<UserDetailsDTO>, UserDetailValidator>();
            services.AddTransient<IValidator<UserAddressDTO>, UserAddressValidator>();

            services.AddTransient<MicaLoginService>();
            services.AddTransient<MotorLoginService>();
            services.AddTransient<AvoLoginService>();
            services.AddTransient<Func<string, ILoginProductService>>(serviceProvider => lkey =>
            {
                switch (lkey)
                {
                    case "Mica":
                        return serviceProvider.GetService<MicaLoginService>();
                    case "Motor":
                        return serviceProvider.GetService<MotorLoginService>();
                    case "Avo":
                        return serviceProvider.GetService<AvoLoginService>();
                    default:
                        return serviceProvider.GetService<MicaLoginService>();

                }
            });

            services.AddTransient<MicaPermissionService>();
            services.AddTransient<MotorPermissionService>();
            services.AddTransient<AvoPermissionService>();
            services.AddTransient<Func<string, IPermissionProductService>>(serviceProvider => pkey =>
            {
                switch (pkey)
                {
                    case "Mica":
                        return serviceProvider.GetService<MicaPermissionService>();
                    case "Motor":
                        return serviceProvider.GetService<MotorPermissionService>();
                    case "Avo":
                        return serviceProvider.GetService<AvoPermissionService>();
                    default:
                        return serviceProvider.GetService<MicaPermissionService>();

                }
            });
            services.AddTransient<MicaRoleService>();
            services.AddTransient<MotorRoleService>();
            services.AddTransient<AvoRoleService>();
            services.AddTransient<Func<string, IRoleProductService>>(serviceProvider1 => rkey =>
            {
                switch (rkey)
                {
                    case "Mica":
                        return serviceProvider1.GetService<MicaRoleService>();
                    case "Motor":
                        return serviceProvider1.GetService<MotorRoleService>();
                    case "Avo":
                        return serviceProvider1.GetService<AvoRoleService>();
                    default:
                        return serviceProvider1.GetService<MicaRoleService>();

                }
            });
            services.AddTransient<MicaProfileService>();
            services.AddTransient<AvoProfileService>();
            services.AddTransient<MotorProfileService>();
            services.AddTransient<Func<string, IUserProductService>>(serviceProvider => rkey =>
            {
                switch (rkey)
                {
                    case "Mica":
                        return serviceProvider.GetService<MicaProfileService>();
                    case "Motor":
                        return serviceProvider.GetService<MotorProfileService>();
                    case "Avo":
                        return serviceProvider.GetService<AvoProfileService>();
                    default:
                        return serviceProvider.GetService<MicaProfileService>();

                }
            });
            services.AddScoped<ILoginService, LoginService>();
            services.AddScoped<IUserProfileService, UserProfileService>();
            services.AddScoped<IRoleService, RoleService>();
            services.AddScoped<IPermissionService, PermissionService>();
        }
    }
}
